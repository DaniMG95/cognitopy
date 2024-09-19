from unittest import TestCase
from cognitopy.cli.config import Config
from cognitopy.exceptions import ExceptionCLIValidateConfig
import tempfile
import toml


class TestConfig(TestCase):

    def test_create_config_with_data(self):
        data = {
            'aws': {
                'key_id': 'test',
                'access_key': 'test_2'
            },
            'cognito': {
                'userpool_id': 'user_test',
                'app_client_id': 'client_id_test',
                'app_client_secret': 'client_secret_test',
                'secret_hash': True
            }
        }

        config = Config(config_data=data)
        self.assertTrue(config.status)
        self.assertTrue(config.secret_hash)
        self.assertEqual(config.userpool_id, 'user_test')
        self.assertEqual(config.app_client_id, 'client_id_test')
        self.assertEqual(config.app_client_secret, 'client_secret_test')
        self.assertEqual(config.key_id, 'test')
        self.assertEqual(config.access_key, 'test_2')

    def test_create_config_with_invalid_data(self):
        data = {
            'aws': {
                'key_id': 'test',
                'access_key': 'test_2'
            },
            'cognito': {
                'userpool_id': 'user_test',
                'app_client_secret': 'client_secret_test',
                'secret_hash': True
            }
        }
        with self.assertRaises(ExceptionCLIValidateConfig) as e:
            Config(config_data=data)
        self.assertEqual(str(e.exception), 'Need this values in config file cognito.app_client_id')

    def test_create_config_with_file(self):
        data = {
            'aws': {
                'key_id': 'test',
                'access_key': 'test_2'
            },
            'cognito': {
                'userpool_id': 'user_test',
                'app_client_id': 'client_id_test',
                'app_client_secret': 'client_secret_test',
                'secret_hash': True
            }
        }
        with tempfile.NamedTemporaryFile(suffix=".toml", delete=False) as my_file:
            with open(my_file.name, "w") as f:
                toml.dump(data, f)

            config = Config(config_file=my_file.name)
            self.assertTrue(config.status)
            self.assertTrue(config.secret_hash)
            self.assertEqual(config.userpool_id, 'user_test')
            self.assertEqual(config.app_client_id, 'client_id_test')
            self.assertEqual(config.app_client_secret, 'client_secret_test')
            self.assertEqual(config.key_id, 'test')
            self.assertEqual(config.access_key, 'test_2')

    def test_create_config_with_file_invalid_data(self):
        data = {
            'aws': {
                'key_id': 'test',
                'access_key': 'test_2'
            },
            'cognito': {
                'userpool_id': 'user_test',
                'app_client_id': 'client_id_test',
                'secret_hash': True
            }
        }
        with tempfile.NamedTemporaryFile(suffix=".toml", delete=False) as my_file:
            with open(my_file.name, "w") as f:
                toml.dump(data, f)

            with self.assertRaises(ExceptionCLIValidateConfig) as e:
                Config(config_file=my_file.name)
            self.assertEqual(str(e.exception), 'Need this values in config file cognito.app_client_secret')
