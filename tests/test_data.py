import unittest
from pygmdata.pygmdata import Data


class TestData(unittest.TestCase):

    def test_setup(self):
        base_url = "http://localhost:8181"
        user_dn = 'CN=dave.borncamp,OU=Engineering,O=Untrusted Example,' \
                  'L=Baltimore,ST=MD,C=US'
        d = Data(base_url, user_dn=user_dn)

        self.assertEqual(d.base_url, base_url)
        self.assertEqual(d.headers['USER_DN'], user_dn)
        self.assertEqual(d.user_dn, user_dn)


if __name__ == '__main__':
    unittest.main()

#"(if (contains email \"dave.borncamp@greymatter.io\")(yield-all)(yield R X))"
op = "{\"label\":\"email match\",\"requirements\":{\"f\":\"if\",\"a\":[{\"f\":\"contains\",\"a\":[{\"v\":\"email\"},{\"v\":\"dave.borncamp@greymatter.io\"}]},{\"f\":\"yield-all\"},{\"f\":\"yield\",\"a\":[{\"v\":\"R\"},{\"v\":\"X\"}]}]}}"
