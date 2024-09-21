import toml
from pathlib import Path
import os
import tempfile
from cognitopy.exceptions import ExceptionCLIValidateConfig


class Config:
    __AWS = "aws"
    __ACCESS_KEY = "access_key"
    __KEY_ID = "key_id"
    __USERPOOL_ID = "userpool_id"
    __COGNITO = "cognito"
    __APP_CLIENT_ID = "app_client_id"
    __APP_CLIENT_SECRET = "app_client_secret"
    __SECRET_HASH = "secret_hash"
    __PARAMS_CONFIG = {
        __AWS: [__KEY_ID, __ACCESS_KEY],
        __COGNITO: [__USERPOOL_ID, __APP_CLIENT_ID, __APP_CLIENT_SECRET, __SECRET_HASH],
    }

    def __init__(self, config_file: str = None, config_data: dict = None):
        self.__data = {}
        self.__path_config = f"{Path.home()}\\.pycognito" if os.name == "nt" else f"{Path.home()}/.pycognito"
        file_config = "\\config.toml" if os.name == "nt" else "/config.toml"
        self.__file_config_path = f"{self.__path_config}{file_config}"

        if not config_data:
            self.__validate_and_load_config(filepath=config_file)
        else:
            self.__write_config(config=config_data)

    def save_config(self) -> None:
        if not os.path.exists(self.__path_config):
            os.mkdir(self.__path_config)
        with open(self.__file_config_path, "w+") as f:
            toml.dump(self.__data, f)

    def __validate_and_load_config(self, filepath: str) -> None:
        errors = []
        if not filepath:
            filepath = self.__file_config_path
        with open(filepath, "r") as f:
            self.__data = toml.load(f)
        for key in self.__PARAMS_CONFIG:
            if key not in self.__data:
                errors.append(key)
            else:
                diff = set(self.__PARAMS_CONFIG[key]) - set(self.__data[key])
                if diff:
                    for diff_item in diff:
                        errors.append(f"{key}.{diff_item}")
        if errors:
            self.__data = {}
            raise ExceptionCLIValidateConfig(f"Need this values in config file {', '.join(errors)}")
        else:
            self.__data[self.__COGNITO][self.__SECRET_HASH] = bool(self.__data[self.__COGNITO][self.__SECRET_HASH])

    def __write_config(self, config: dict) -> None:
        with tempfile.NamedTemporaryFile(suffix=".toml", delete=False) as my_file:
            with open(my_file.name, "w") as f:
                toml.dump(config, f)
            self.__validate_and_load_config(filepath=my_file.name)
        try:
            os.unlink(my_file.name)
        except Exception:
            pass

    def __getitem__(self, key: str):
        return self.__data[key]

    @property
    def status(self) -> bool:
        return bool(self.__data)

    @property
    def key_id(self) -> str:
        return self.__data[self.__AWS][self.__KEY_ID]

    @property
    def access_key(self) -> str:
        return self.__data[self.__AWS][self.__ACCESS_KEY]

    @property
    def userpool_id(self) -> str:
        return self.__data[self.__COGNITO][self.__USERPOOL_ID]

    @property
    def app_client_id(self) -> str:
        return self.__data[self.__COGNITO][self.__APP_CLIENT_ID]

    @property
    def app_client_secret(self) -> str:
        return self.__data[self.__COGNITO][self.__APP_CLIENT_SECRET]

    @property
    def secret_hash(self) -> bool:
        return self.__data[self.__COGNITO][self.__SECRET_HASH]

    @classmethod
    def load_config(cls):
        try:
            config = cls()
        except FileNotFoundError:
            raise ExceptionCLIValidateConfig("Need configurate cognito, run command init before running this command.")
        else:
            if "AWS_ACCESS_KEY_ID" not in os.environ or os.environ["AWS_ACCESS_KEY_ID"] != config.key_id:
                os.environ["AWS_ACCESS_KEY_ID"] = config.key_id
            if "AWS_SECRET_ACCESS_KEY" not in os.environ or os.environ["AWS_SECRET_ACCESS_KEY"] != config.access_key:
                os.environ["AWS_SECRET_ACCESS_KEY"] = config.access_key
        return config
