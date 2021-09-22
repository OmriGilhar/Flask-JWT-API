from unittest import main, TestCase

from src.app import app, db
import json

# set our application to testing mode
app.testing = True

use_case_1 = [
    {
        "name": "device",
        "strVal": "iPhone",
        "metadata": "not interesting"
        },
    {
        "name": "isAuthorized",
        "boolVal": "false",
        "lastSeen": "not interesting"
    }
]
user_cred = {
    'user': 'User',
    'password': '123456'
}


class TestAPI(TestCase):
    def setUp(self) -> None:
        db.create_all()

    def test_create_data_unauthorized(self):
        with app.test_client() as client:
            result = client.post(
                '/data',
                data=json.dumps(use_case_1)
            )
            self.assertEqual(result.status_code, 401)

    def test_create_data_flow(self):
        with app.test_client() as client:
            client.post(
                '/signup',
                data=user_cred
            )

            res = client.post(
                '/login',
                data=user_cred
            )
            user_tok = res.get_json().get('token')
            result = client.post(
                '/data',
                json=use_case_1,
                headers={
                          'x-access-token': user_tok,
                }
            )
            expected = {"device": "iPhone", "isAuthorized": "false"}
            self.assertEqual(expected, result.get_json())


if __name__ == "__main__":
    main()
