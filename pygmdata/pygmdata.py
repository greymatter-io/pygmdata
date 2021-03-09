import copy
import os
import io
import sys
import requests
from requests_toolbelt import MultipartEncoder
import mimetypes
import json
from json import JSONDecodeError
from pathlib import Path
from PIL import Image
import logging
import urllib3
# Does not see DI2E as a valid signing authority so suppress that warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Data:
    def __init__(self, base_url, **kwargs):
        """Class to interact with GM-Data.

        :param base_url: URL that Data lives at. All interactions will append
            to this URL to interact with Data (ex base_url + "/self")
        :param kwargs: Extra arguments to be supplied (case insensitive):

            - USER_DN - Your USER_DN to be used for interacting with Data.
                This will be added to the header of every request.
            - logfile - File to save the log to. If not specified
            - log_level - Level of verbosity to log. Defaults to warning.
                Can be integer or string.
            - security - The default security policy to use. This can be
                overidden when writing files. If not specified it will use:
                ::

                    {"label": "DECIPHER//GMDATA",
                     "foreground": "#FFFFFF",
                     "background": "green"}

            - cert - Certificate to use in pem format.
            - key - keyfile to use in pem format.
            - trust - CA trust to use to make TLS connections.
            - repopulate - A hack to get around changes that may have happened
                in Data between file uploads and hierarchy updates
        """
        self.base_url = base_url
        self.headers = {}
        self.data = None
        self.hierarchy = {}
        self.log = None
        self.cert = None
        self.key = None
        self.trust = False
        self.repopulate = True
        level = "warning"
        self.default_security = {"label": "DECIPHER//GMDATA",
                                 "foreground": "#FFFFFF",
                                 "background": "green"}

        for key, value in kwargs.items():
            if "user_dn" == key.lower():
                self.headers["USER_DN"] = value
                self.user_dn = value
            if "logfile" == key.lower():
                self.log = self.start_logger(value)
            if "log_level" == key.lower():
                level = value
            if "security" == key.lower():
                self.default_security = value
            if "cert" == key.lower():
                self.cert = value
            if "key" == key.lower():
                self.key = value
            if "trust" == key.lower():
                self.trust = value
            if "repopulate" == key.lower():
                self.repopulate = value
        if not self.log:
            self.log = self.start_logger()
        # Set the level now that the logger exists
        self.set_log_level(level)

        try:
            self.populate_hierarchy("/")
        except Exception as e:
            self.log.error("Could not populate hierarchy. Check the base_url")
            raise e

    def get_config(self):
        """Hit the `/config` endpoint to probe how Data is setup

        :return: json from the config endpoint
        """
        r = requests.get(self.base_url + "/config", headers=self.headers,
                         cert=(self.cert, self.key), verify=self.trust)

        return r.json()

    def get_self_identify(self, object_policy=None,
                          original_object_policy=None):
        """Identify self and make user directory

        :param object_policy: Object policy to use to create home directory.
            Make sure that "U" permissions are given, If not supplied it
            will try to use the policy of the root directory which may
            not grant the user "U" permissions.
        :param original_object_policy: Field to be put into the
            originalobjectpolicy field. This can be lisp or OPA/Rego depending
            on the version of GM Data that is in use.
        :return: True if successful
        """
        configs = self.get_config()
        namespace_userfield = configs["GMDATA_NAMESPACE_USERFIELD"]
        root = configs["GMDATA_NAMESPACE"]

        self_json_values = self.get_self()

        user_folder_name = json.loads(self_json_values)['values'][namespace_userfield][0]
        user_folder = "/{}/{}".format(root, user_folder_name)
        return self.make_directory_tree(user_folder,
                                        object_policy=object_policy,
                                        original_object_policy=original_object_policy)

    def get_self(self):
        """Hit GM Data's self endpoint.

        :return: Description of the user's credential token in the format of
            ::

                {"label":USER_DN,"exp":1608262398,"iss":"greymatter.io",
                "values":{"email":["dave.borncamp@greymatter.io"],
                "org":["greymatter.io"]}}

        """
        r = requests.get(self.base_url + "/self", headers=self.headers,
                         cert=(self.cert, self.key), verify=self.trust)
        ret = r.text
        r.close()
        return ret

    def get_props(self, path):
        """Get the properties of a given Data object.

        This essentially returns the metadata of a given object in Data.

        :param path: Directory path that the object is nestled in.

        :return: json of properties if it exists, None if not.
            ::

                {'tstamp': '1668e4d701ac18a4',
                 'userpolicy': {'label': 'CN=dave.borncamp,OU=Engineering,O=Untrusted Example,L=Baltimore,ST=MD,C=US'},
                 'jwthash': '368734e0d26fe381726932a727a04c9f4db9cca995e2341151d2c664e636b8f3',
                 'schemaversion': 10,
                 'name': 'dave.borncamp@greymatter.io',
                 'action': 'C',
                 'oid': '1668e4d701979c80',
                 'parentoid': '1668e15c6792db54',
                 'expiration': '7fffffffffffffff',
                 'checkedtstamp': '1668e15c679cd280',
                 'objectpolicy': {'requirements': {'f': 'if',
                   'a': [{'f': 'contains',
                   'a': [{'v': 'email'}, {'v': 'dave.borncamp@greymatter.io'}]},
                    {'f': 'yield-all'},
                    {'f': 'yield', 'a': [{'v': 'R'}, {'v': 'X'}]}]}},
                 'derived': {},
                 'security': {'label': 'DECIPHER//GMDATA',
                  'foreground': '#FFFFFF',
                  'background': 'green'},
                 'originalobjectpolicy': '(if (contains email "dave.borncamp@greymatter.io")(yield-all)(yield R X))',
                 'policy': {'policy': ['R', 'X']},
                 'cluster': 'default'}
        """
        path = Path(path)
        oid = self.find_file(str(path))

        self.log.debug("Looking for props of: {}, oid {}".format(path, oid))
        if not oid:
            if str(path) == path.root:
                raise Exception('Unable to locate the root directory')
            self.log.info("Path {} not found, cannot get props"
                          "".format(path))
            return None

        r = requests.get(self.base_url + '/props/{}'.format(oid),
                         headers=self.headers,
                         cert=(self.cert, self.key), verify=self.trust)
        r.close()
        return r.json()

    def get_list(self, path, oid=None):
        """Get the contents of a given path.

        This gives the most recent tstamp by oid. The result is sorted by oid,
        and should only have one historical object per oid with highest tstamp.

        Note: Listings of files will return None

        :param path: Directory path that the object is nestled in.
        :param oid: Object ID of the thing to list

        :return: json of listing if it exists, None if not
        """
        if oid:
            url = self.base_url + '/list/{}'.format(oid)
        else:
            path = Path(path)
            oid = self.find_file(str(path))

            self.log.debug("Looking for listing of: {}, oid {}".format(path,
                                                                       oid))
            url = self.base_url + '/list/{}'.format(oid)
            if not oid:
                if str(path) == path.root:
                    raise Exception('Unable to locate the parent directory')
                self.log.info("Path {} not found, cannot get listing"
                              "".format(path))
                return None

        r = requests.get(url, headers=self.headers, cert=(self.cert, self.key),
                         verify=self.trust)
        self.log.debug("URL: {}".format(r.request.url))
        self.log.debug("Body: {}".format(r.request.body))
        self.log.debug("Headers: {}".format(r.request.headers))
        r.close()
        if r.ok:
            return r.json()
        return None

    def populate_hierarchy(self, path):
        """Populate the internal hierarchy structure.

        Every GM Data data object has an Object ID, including directories and
        files. This serves as a way to keep track of individual listings
        that can be easily accessed through an API call.

        This function recursively searches the Data directory tree starting
        at the given oid and calls `list` on it.

        :param path: Directory path that the object is nestled in.
            This will be prepended to the object's name and used as a key
            in the internal hierarchy dictionary.
            Always starts out as `/` then builds to `/world` and so forth until
            the entire listing in Data is mapped.

        """
        if path == '/' or path == "":
            list_json = self.get_list(path, oid=1)
            path = ''
        else:
            list_json = self.get_list(path)
        for j in list_json:
            filepath = "{}/{}".format(path, j['name'])
            self.hierarchy[filepath] = j['oid']
            self.log.debug("path: {}, oid: {}".format(filepath, j['oid']))

            # stop if it is a file
            try:
                _ = j['isfile']
                continue
            except KeyError:
                self.populate_hierarchy(filepath)

    def create_meta(self, data_filename, object_policy=None,
                    original_object_policy=None, **kwargs):
        """Create the meta data for an object to be uploaded

        Will determine if the action is to create or update the object
        and create all of the necessary metadata needed for making/updating
        it.

        :param data_filename: The filename that will be used in Data
        :param object_policy: Object Policy to use. Will update an existing
            object with this value or will make a new object with this policy.
            If not supplied for either, it will make a best effort to
            come up with a good response
        :param original_object_policy: Field to be put into the
            originalobjectpolicy field. This can be lisp or OPA/Rego depending
            on the version of GM Data that is in use.
        :param kwargs: extra keywords to be set:
            - security - The security tag of the given file. If not supplied
            it will keep what is already there or it will use the field
            from the parent if creating a new file.
            - mimetype - Mimetype to be used as a header value to be uploaded.
            If not supplied it will make it's best guess at the value.
        :return: Metadata dictionary
        """
        self.log.debug("Create Metadata object_policy {}".format(object_policy))
        # check to see if it exists. If so, it is an update else create
        oid = self.find_file(data_filename)
        if isinstance(object_policy, str):
            object_policy = json.loads(object_policy)

        self.log.debug("data file is: {}".format(data_filename))
        mimetype = mimetypes.guess_type(data_filename)[0]
        self.log.debug("Mimetype based on target file: {}".format(mimetype))
        if "mimetype" in kwargs.keys():
            mimetype = kwargs["mimetype"]
        elif "local_filename" in kwargs.keys():
            local_type = mimetypes.guess_type(kwargs["local_filename"])[0]
            if local_type is not None:
                self.log.debug("Guessing type from local: {}".format(local_type))
                mimetype = local_type
        self.log.debug("The determined mimetype is: {}".format(mimetype))
        # make the metadata of the upload, decide if it is an update or create
        if oid:
            meta = self.get_props(data_filename)
            self.log.debug("Found the props of a file for updating. "
                           "OID: {}".format(oid))
            meta['action'] = "U"
            meta['mimetype'] = mimetype
            if object_policy:
                meta['objectpolicy'] = object_policy
            if original_object_policy:
                meta['originalobjectpolicy'] = original_object_policy
            try:
                if kwargs['security']:
                    meta['security'] = kwargs['security']
            except KeyError:
                pass
        else:
            # get the oid of the parent folder to upload into
            path = Path(data_filename)
            oid = self.find_file(str(path.parent))
            self.log.debug("New file under parent OID: {}".format(path.parent))
            if not oid:
                oid = self.make_directory_tree(str(path.parent),
                                               object_policy=object_policy,
                                               original_object_policy=original_object_policy)
            if not object_policy or original_object_policy:
                props_json = self.get_props(path.parent)
                if not object_policy and not original_object_policy:
                    object_policy = props_json['objectpolicy']
                if not original_object_policy:
                    try:
                        original_object_policy = props_json['originalobjectpolicy']
                    except KeyError:
                        self.log.info("No original object policy found.")
                        original_object_policy = ""
                self.log.debug("Using assumed OP {} from parent, "
                               "oid {}".format(object_policy, oid))
            self.log.debug("Using given OP {} from "
                           "oid {}".format(object_policy, oid))
            meta = {
                "action": "C",
                "name": path.name,
                "parentoid": oid,
                "isFile": True,
                "originalobjectpolicy": original_object_policy,
                "mimetype": mimetype
            }
            if object_policy:
                meta["objectpolicy"] = object_policy

            try:
                if kwargs['security']:
                    meta['security'] = kwargs['security']
            except KeyError:
                props_json = self.get_props(path.parent)
                meta['security'] = props_json['security']
                self.log.debug("Using security: {}".format(meta['security']))

        return meta

    def upload_file(self, local_filename, data_filename, object_policy=None,
                    original_object_policy=None, **kwargs):
        """Upload a file from the local filesystem to GM-Data.

        This will upload a file from the local file system to GM-Data.
        If the file already exists, it will update the file.
        If it does not exist, it will create a new file in the given
        directory in GM-Data.

        :param local_filename: Filename to upload on the local filesystem
        :param data_filename: Filename of the destination in GM Data
        :param object_policy: Object Policy permissions for the file to have.
            If not supplied and updating a file, it will keep what is already in
            Data. If creating a new file and not supplied, it will likely fail
            as a file will be uploaded that cannot be accessed by anyone.
        :param original_object_policy: Field to be put into the
            originalobjectpolicy field. This can be lisp or OPA/Rego depending
            on the version of GM Data that is in use.
        :param kwargs: extra keywords to be set:
            - security - The security tag of the given file. If not supplied
            it will keep what is already there or it will use the field
            from the parent if creating a new file.
        :return: False if request doesn't succeed or cannot be built
            True if it succeeds
        """
        self.log.debug("Uploading file {} to {} op {}".format(local_filename,
                                                              data_filename,
                                                              object_policy))
        self.log.debug("{}".format(type(object_policy)))
        mimetype = mimetypes.guess_type(data_filename)
        meta = self.create_meta(data_filename, local_filename=local_filename,
                                object_policy=object_policy,
                                original_object_policy=original_object_policy,
                                **kwargs)

        self.log.debug("Returned Metadata: {}".format(meta))

        # lets get to writing! Do a multipart upload
        with open(local_filename, 'rb') as f:
            multipart_data = MultipartEncoder(
                fields={"meta": json.dumps([meta]),
                        "blob": (local_filename, f, mimetype[0])}
            )

            headers = copy.copy(self.headers)
            headers['Content-length'] = str(os.path.getsize(local_filename))
            headers['Content-Type'] = multipart_data.content_type
            r = requests.post(self.base_url+"/write", data=multipart_data,
                              headers=headers, cert=(self.cert, self.key),
                              verify=self.trust)
        self.log.debug("The sent request")
        self.log.debug("URL: {}".format(r.request.url))
        self.log.debug("Body: {}".format(r.request.body))
        self.log.debug("Headers: {}".format(r.request.headers))
        self.log.debug("Response")
        self.log.debug(r.status_code)
        self.log.debug(r.text)

        ok = r.ok
        r.close()
        if ok:
            self.hierarchy[data_filename] = r.json()[0]["oid"]

        return ok

    def make_directory_tree(self, path, object_policy=None,
                            original_object_policy=None, **kwargs):
        """Recursively create directories in GM Data.

        :param path: Path to be created in GM Data
        :param object_policy: A LISP statement of the Object Policy to be
            used for all folders that will be created in 
        :param kwargs: extra keywords to be set:
            - security - The security tag of the given file. If not supplied
            it will keep what is already there or it will use the field
            from the parent if creating a new file.
        :param original_object_policy: Field to be put into the
            originalobjectpolicy field. This can be lisp or OPA/Rego depending
            on the version of GM Data that is in use.
        :return: oid on success
        """
        path = Path(path)
        oid = self.find_file(str(path.parent))
        if isinstance(object_policy, str):
            object_policy = json.loads(object_policy)

        self.log.debug("Looking for {}, oid {}".format(path.parent, oid))
        if not oid:
            if str(path) == path.root:
                raise Exception('Unable to locate the root directory')
            self.log.debug("Path {} not found, creating"
                           " parent".format(path.parent))
            self.make_directory_tree(str(path.parent),
                                     object_policy=object_policy,
                                     original_object_policy=original_object_policy,
                                     **kwargs)

        oid = self.find_file(str(path.parent))

        self.log.debug("New file under parent OID: {}, name: {}"
                       "".format(oid, path.name))

        body = {
            "action": "C",
            "name": path.name,
            "parentoid": oid,
            "isFile": False
        }

        if object_policy:
            body['objectpolicy'] = object_policy
            body['originalobjectpolicy'] = object_policy
        # just overwrite what we just did if we need to
        if original_object_policy:
            body['originalobjectpolicy'] = original_object_policy
        if "objectpolicy" not in body.keys() or\
                'originalobjectpolicy' not in body.keys():
            prop_json = self.get_props(path.parent)
            self.log.debug("The parsed OP: {}".format(prop_json['objectpolicy']))
            body['objectpolicy'] = prop_json['objectpolicy']

        if 'security' in kwargs:
            body['security'] = kwargs['security']
        else:
            body['security'] = self.default_security

        files = {'file': ('meta', json.dumps([body]))}
        r = requests.post(self.base_url + "/write", files=files,
                          headers=self.headers, cert=(self.cert, self.key),
                          verify=self.trust)

        self.log.debug("The sent request")
        self.log.debug("URL: {}".format(r.request.url))
        self.log.debug("Body: {}".format(r.request.body))
        self.log.debug("Headers: {}".format(r.request.headers))
        self.log.debug("Response")
        self.log.debug(r.status_code)
        self.log.debug(r.raw)

        ok = r.ok
        r.close()
        if ok:
            oid = r.json()[0]["oid"]
            self.hierarchy[path.as_posix()] = oid
            return oid

        return False

    def get_part(self, data_filename, object_policy=None):
        """Get the file part append for a multi part file

        :param data_filename: Filename in GM Data
        :param object_policy: optional object policy to use
        :return: File part like 'aab'
        """
        self.log.debug(self.hierarchy)
        oid = self.find_file(data_filename)
        self.log.debug("OID for part: {} {}".format(data_filename, oid))
        if not oid:
            # this does not exist yet
            # yes, we want a directory named for the file
            oid = self.make_directory_tree(data_filename,
                                           object_policy=object_policy)
            self.log.debug("'File' does not exist yet, so created it."
                           " oid {}".format(oid))
            self.populate_hierarchy('/')
            return "aaa"
        else:
            # download and delete the file, rename if it is a file
            self.log.debug("Found in hierarchy. oid {}".format(oid))
            prop_json = self.get_props(data_filename)
            self.log.debug("Returned props: {}".format(prop_json))
            try:
                if prop_json['isfile']:
                    self.log.error("It's already a file!! Not implemented!")
                    return None
            except KeyError:
                # not a file, this is the oid we want
                self.log.debug("Got the file we wanted, not is file. "
                               "OID: {}".format(prop_json['oid']))
                pass
        # figure out the next part number
        # start by listing them off
        resp_json = self.get_list(data_filename)
        self.log.debug("The listing: {}".format(resp_json))
        # get only the filenames
        names = [name['name'] for name in resp_json if 'isfile' in name.keys()]
        names.sort()
        self.log.debug("names: {}".format(names))

        # take the last one and increment it
        if len(names) == 0:
            return "aaa"
        else:
            return self._increment_str(names[-1].split(".")[0])

    def append_file(self, local_filename, data_filename, object_policy=None):
        """Append an uploaded file with another file on disk

        :param local_filename: Filename on disk that will be appended to the
            data_filename
        :param data_filename: Filename to append the new file to
        :param object_policy: Object Policy to use. Will update an existing
            object with this value or will make a new object with this policy.
            If not supplied for either, it will make a best effort to
            come up with a good response
        :return: True on success
        """
        part = self.get_part(data_filename, object_policy=object_policy)

        if part:
            a = self.upload_file(local_filename, "{}/{}".format(data_filename,
                                                                part),
                                 object_policy=object_policy)
            return a
        return False

    def append_data(self, data, data_filename, object_policy=None,
                    original_object_policy=None):
        """Append the given filename with the given data in memory

        :param data: Data to append to a file. Remember to add line endings
            if needed.
        :param data_filename: Target filename to update
        :param object_policy: Object Policy to use. Will update an existing
            object with this value or will make a new object with this policy.
            If not supplied for either, it will make a best effort to
            come up with a good response
        :return: True on success
        """
        part = self.get_part(data_filename, object_policy=object_policy)

        if not part:
            self.log.warning("Did not get a good part back to append!")
            return False
        mimetype = mimetypes.guess_type(data_filename)[0]

        meta = self.create_meta("{}/{}".format(data_filename, part),
                                object_policy=object_policy,
                                original_object_policy=original_object_policy,
                                mimetype=mimetype)

        if isinstance(data, str):
            with io.StringIO(data) as f:
                multipart_data = MultipartEncoder(
                    fields={"meta": json.dumps([meta]),
                            "blob": ("{}/{}".format(data_filename, part),
                                     f, mimetype)}
                )

                headers = copy.copy(self.headers)
                headers['Content-Type'] = multipart_data.content_type
        else:
            with io.BytesIO(data) as f:
                multipart_data = MultipartEncoder(
                    fields={"meta": json.dumps([meta]),
                            "blob": ("{}/{}".format(data_filename, part),
                                     f, mimetype)}
                )

                headers = copy.copy(self.headers)
                headers['Content-Type'] = multipart_data.content_type
        r = requests.post(self.base_url + "/write", data=multipart_data,
                          headers=headers, cert=(self.cert, self.key),
                          verify=self.trust)

        self.log.debug("The append_data sent request")
        self.log.debug("URL: {}".format(r.request.url))
        self.log.debug("Body: {}".format(r.request.body))
        self.log.debug("Headers: {}".format(r.request.headers))

        try:
            self.log.debug("Response")
            self.log.debug(r.status_code)
            self.log.debug(r.json())
            if r.ok:
                self.populate_hierarchy('/')
            return r.ok
        except JSONDecodeError:
            return False

    def download_file(self, file, local_filename, chunk_size=8192):
        """Downloads a file onto the local file system.

        Streams a file in chunks of 8192 to write the given file onto the
        filesystem. Streaming with chunks of this size can save lots of
        memory when downloading large files.

        :param file: File within GM-Data to download
        :param local_filename: Filename to be written onto the local filesystem
        :param chunk_size: Size of chunks to be used. Defaults to 8192
        :return: Written filename on success
        """
        oid = self.find_file(file)
        if oid:
            with requests.get(self.base_url+"/stream/{}".format(oid),
                              headers=self.headers, stream=True,
                              cert=(self.cert, self.key),
                              verify=self.trust) as r:
                r.raise_for_status()
                with open(local_filename, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=chunk_size):
                        f.write(chunk)
            return local_filename
        else:
            self.log.warning("Cannot find file in GM-Data to download.")

    def get_byte_steam(self, file):
        """Get a file as a data stream into memory

        :param file: File name within GM-Data to download
        :return: bytestream of file contents
        """
        oid = self.find_file(file)

        if oid:
            r = requests.get(self.base_url+"/stream/{}".format(oid),
                             headers=self.headers, stream=True,
                             cert=(self.cert, self.key), verify=self.trust)
            r.raise_for_status()
            r.raw.decode_content = True
            return io.BytesIO(r.content)
        else:
            self.log.warning("Cannot find file in GM-Data to download.")

    def stream_file(self, file):
        """Get a file loaded into memory.

        Look at the Content-Type header and parse the returned variable
        accordingly:

        - `image/jpeg` return a PIL image
        - `application/json` return a dictionary in json format
        - `text/plain` return decoded text of object
        - Anything else return a buffer of the content

        :param file: File name within GM-Data to download
        :return: Object
        """
        oid = self.find_file(file)

        if not oid:
            self.log.warning("Cannot find file in GM-Data to download.")
            return None

        r = requests.get(self.base_url+"/stream/{}".format(oid),
                         headers=self.headers, stream=True,
                         cert=(self.cert, self.key), verify=self.trust)
        r.raise_for_status()
        r.raw.decode_content = True

        if r.headers['Content-Type'] == 'image/jpeg':
            im = Image.open(r.raw)
            return im
        if r.headers['Content-Type'] == 'application/json':
            return r.json()
        if r.headers['Content-Type'] == 'text/plain':
            return r.content.decode()
        return io.BytesIO(r.content)

    def stream_upload_string(self, s, data_filename, object_policy=None,
                             original_object_policy=None, **kwargs):
        """Upload a string into file from memory

        :param s: Data to upload to a file.
        :param data_filename: Target filename to upload to
        :param object_policy: Object Policy to use. Will update an existing
            object with this value or will make a new object with this policy.
            If not supplied for either, it will make a best effort to
            come up with a good response
        :param original_object_policy: Field to be put into the
            originalobjectpolicy field. This can be lisp or OPA/Rego depending
            on the version of GM Data that is in use.
        :return: True on success
        """
        if isinstance(s, str):
            with io.StringIO(s) as f:
                return self.stream_upload(f, data_filename, object_policy,
                                          original_object_policy, **kwargs)

    def stream_upload(self, data_buf, data_filename, object_policy=None,
                      original_object_policy=None, **kwargs):
        """Upload a file buffer from memory as a given filename

        :param data_buf: Buffer of data to upload to a file.
        :param data_filename: Target filename to upload to
        :param object_policy: Object Policy to use. Will update an existing
            object with this value or will make a new object with this policy.
            If not supplied for either, it will make a best effort to
            come up with a good response.
        :param original_object_policy: Field to be put into the
            originalobjectpolicy field. This can be lisp or OPA/Rego depending
            on the version of GM Data that is in use.
        :return: True on success
        """
        self.log.debug("Uploading file {} op {}".format(data_filename,
                                                        object_policy))
        meta = self.create_meta(data_filename, object_policy=object_policy,
                                original_object_policy=original_object_policy,
                                **kwargs)

        mimetype = mimetypes.guess_type(data_filename)

        multipart_data = MultipartEncoder(
            fields={"meta": json.dumps([meta]),
                    "blob": (data_filename,
                             data_buf, mimetype[0])}
        )

        headers = copy.copy(self.headers)
        headers['Content-Type'] = multipart_data.content_type
        r = requests.post(self.base_url + "/write", data=multipart_data,
                          headers=headers, cert=(self.cert, self.key),
                          verify=self.trust)

        self.log.debug("The append_data sent request")
        self.log.debug("URL: {}".format(r.request.url))
        self.log.debug("Body: {}".format(r.request.body))
        self.log.debug("Headers: {}".format(r.request.headers))
        self.log.debug("Response")
        self.log.debug(r.status_code)
        self.log.debug(r.text)
        r.close()

        if r.ok:
            self.hierarchy[data_filename] = r.json()[0]["oid"]

        return r.ok

    # --- Utility functions

    def find_file(self, filename):
        """Find a given file within the file hierarchy

        Try to find a file within the file hierarchy, if it is not immediately
        found, repopulate the hierarchy and try again. If it is still
        not found, return None

        :param filename: Filename to be found within GM Data
        :return: The GM Data oid if found or None if not
        """
        try:
            oid = self.hierarchy[filename]
            return oid
        except KeyError:
            # Maybe it got populated since this class last checked
            self.log.debug("Not found initially, trying to re-populate")
            if not self.repopulate:
                return None

        # Try repopulating the index to see if it is there now
        self.populate_hierarchy("/")

        try:
            oid = self.hierarchy[filename]
            return oid
        except KeyError:
            self.log.debug("Nothing matching that filename found")
            return None

    @staticmethod
    def start_logger(name="pygmdata", logfile=None):
        """Start logging what is going on

        :param name: Name of the logger to use. Defaults to "pygmdata"
        :param logfile: Name of output logfile. Default to not saving.
        :return: logfile written to disk
        """
        log = logging.getLogger(name)

        fmt = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        # create the logging file handler
        logging.basicConfig(filename=logfile, format=fmt)

        # -- handler for STDOUT
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.INFO)
        formatter = logging.Formatter(fmt)
        ch.setFormatter(formatter)
        logging.getLogger().addHandler(ch)

        return log

    def set_log_level(self, level):
        """ Set the log level for the log

        :param level: Level of verbosity to log. Defaults to warning.
            Can be integer or string.
        :return: None
        """
        if isinstance(level, int):
            self.log.setLevel(level)
            return

        if level.lower() == "info":
            self.log.setLevel(logging.getLevelName('INFO'))
        elif level.lower() == 'debug':
            self.log.setLevel(logging.getLevelName('DEBUG'))
        elif level.lower() == 'warning':
            self.log.setLevel(logging.getLevelName('WARNING'))
        elif level.lower() == 'error':
            self.log.setLevel(logging.getLevelName('ERROR'))

    @staticmethod
    def _increment_char(c):
        """
        Increment an uppercase character, returning 'a' if 'z' is given
        """
        return chr(ord(c) + 1) if c != 'z' else 'a'

    def _increment_str(self, s):
        lpart = s.rstrip('z')
        num_replacements = len(s) - len(lpart)
        new_s = lpart[:-1] + self._increment_char(lpart[-1]) if lpart else 'a'
        new_s += 'a' * num_replacements
        return new_s
