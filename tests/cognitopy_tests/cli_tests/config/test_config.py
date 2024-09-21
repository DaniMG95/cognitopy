from unittest import TestCase
from unittest.mock import patch, Mock, call, mock_open
from cognitopy.cli.config import Config
from cognitopy.exceptions import ExceptionCLIValidateConfig
import tempfile
import toml
import os


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
        self.assertEqual('user_test', config.userpool_id)
        self.assertEqual('client_id_test', config.app_client_id)
        self.assertEqual('client_secret_test', config.app_client_secret)
        self.assertEqual('test', config.key_id)
        self.assertEqual('test_2', config.access_key)

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
        self.assertEqual('Need this values in config file cognito.app_client_id', str(e.exception))

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
            self.assertEqual('user_test', config.userpool_id)
            self.assertEqual('client_id_test', config.app_client_id)
            self.assertEqual('client_secret_test', config.app_client_secret)
            self.assertEqual('test', config.key_id)
            self.assertEqual('test_2', config.access_key)

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
            self.assertEqual('Need this values in config file cognito.app_client_secret', str(e.exception))

    @patch('os.name', 'posix')
    @patch('os.path.exists', return_value=False)
    @patch('os.mkdir')
    @patch('pathlib.Path.home', return_value='/home/test')
    def test_save_config(self, mock_home: Mock, mock_mkdir: Mock, mock_exists: Mock):

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
        with (patch('cognitopy.cli.config.config.toml.dump') as mock_toml_dump,
              patch('cognitopy.cli.config.config.open') as mock_open_file):
            config.save_config()
        self.assertEqual([call('/home/test/.pycognito')], mock_mkdir.call_args_list)
        self.assertEqual([call('/home/test/.pycognito/config.toml', 'w+')], mock_open_file.call_args_list)
        self.assertEqual(1, mock_toml_dump.call_count)
        self.assertEqual(data, mock_toml_dump.call_args_list[0][0][0])
        self.assertEqual(1, mock_exists.call_count)
        self.assertEqual(1, mock_home.call_count)

    @patch('os.name', 'posix')
    @patch('os.path.exists', return_value=True)
    @patch('os.mkdir')
    @patch('pathlib.Path.home', return_value='/home/test')
    def test_save_config_exist_dir(self, mock_home: Mock, mock_mkdir: Mock, mock_exists: Mock):
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
        with (patch('cognitopy.cli.config.config.toml.dump') as mock_toml_dump,
              patch('cognitopy.cli.config.config.open') as mock_open_file):
            config.save_config()
        self.assertEqual(0, mock_mkdir.call_count)
        self.assertEqual([call('/home/test/.pycognito/config.toml', 'w+')], mock_open_file.call_args_list)
        self.assertEqual(1, mock_toml_dump.call_count)
        self.assertEqual(data, mock_toml_dump.call_args_list[0][0][0])
        self.assertEqual(1, mock_exists.call_count)
        self.assertEqual(1, mock_home.call_count)

    @patch('cognitopy.cli.config.config.open', new_callable=mock_open, read_data="""
    [aws]
    key_id = "test"
    access_key = "test_2"   
    [cognito]
    userpool_id = "test_user"
    app_client_id = "test_client"
    app_client_secret = "test_secret"
    secret_hash = true
    """)  # noqa: W291
    @patch('pathlib.Path.home', return_value='/home/test')
    @patch.dict('os.environ', {}, clear=True)
    def test_load_config(self, mock_home: Mock, mock_open_file: Mock):
        Config.load_config()

        self.assertEqual('test', os.environ.get('AWS_ACCESS_KEY_ID'))
        self.assertEqual('test_2', os.environ.get('AWS_SECRET_ACCESS_KEY'))
        self.assertEqual(1, mock_home.call_count)
        self.assertEqual(1, mock_open_file.call_count)

    @patch('cognitopy.cli.config.config.open', new_callable=mock_open, read_data="""
    [aws]
    key_id = "test"
    access_key = "test_2"
    """)
    @patch('pathlib.Path.home', return_value='/home/test')
    @patch.dict('os.environ', {}, clear=True)
    def test_load_config_with_error_validation(self, mock_home: Mock, mock_open_file: Mock):
        with self.assertRaises(ExceptionCLIValidateConfig) as e:
            Config.load_config()

        self.assertEqual('Need this values in config file cognito', str(e.exception))
        self.assertEqual({}, os.environ)
        self.assertEqual(1, mock_home.call_count)
        self.assertEqual(1, mock_open_file.call_count)

    @patch('pathlib.Path.home', return_value='/home/test123')
    @patch.dict('os.environ', {}, clear=True)
    def test_load_config_with_error_file_not_exist(self, mock_home: Mock):
        with self.assertRaises(ExceptionCLIValidateConfig) as e:
            Config.load_config()

        self.assertEqual('Need configurate cognito, run command init before running this command.',
                         str(e.exception))
        self.assertEqual({}, os.environ)
        self.assertEqual(1, mock_home.call_count)
