import toml
from pathlib import Path
import os
from cognitopy.exceptions import ExceptionCLIValidateConfig


class Config:
    __ACCESS_KEY = "access_key"
    __KEY_ID = "key_id"
    __USERPOOL_ID = "userpool_id"
    __APP_CLIENT_ID = "app_client_id"
    __APP_CLIENT_SECRET = "app_client_secret"
    __SECRET_HASH = "secret_hash"
    __PARAMS_CONFIG = [__KEY_ID, __ACCESS_KEY, __USERPOOL_ID, __APP_CLIENT_ID, __APP_CLIENT_SECRET, __SECRET_HASH]
    __PATH_CONFIG = f"{Path.home()}\\.pycognito" if os.name == "nt" else f"{Path.home()}/.pycognito"
    __FILE_CONFIG = "\\config.toml" if os.name == "nt" else "/config.toml"
    __FILE_CONFIG_PATH = f"{__PATH_CONFIG}{__FILE_CONFIG}"

    def __init__(self, name: str = None):
        self.__data = {}
        self.__name = name

    @classmethod
    def save_config(cls) -> None:
        if not os.path.exists(cls.__PATH_CONFIG):
            os.mkdir(cls.__PATH_CONFIG)
        with open(cls.__FILE_CONFIG_PATH, "w+") as f:
            toml.dump({}, f)

    @classmethod
    def validate_file(cls, filepath: str) -> None:
        errors = ""
        data_config = {}
        if os.path.exists(cls.__FILE_CONFIG_PATH):
            with open(cls.__FILE_CONFIG_PATH, "r") as f:
                data_config = toml.load(f)

        with open(filepath, "r") as f:
            data = toml.load(f)
        for name in data.keys():
            if name in data_config.keys():
                raise ExceptionCLIValidateConfig(f"This name config {name} already exists in config file")
            if not isinstance(data[name], dict):
                raise ExceptionCLIValidateConfig(f"Need these values {', '.join(cls.__PARAMS_CONFIG)} into in name "
                                                 "config")
            diff = set(cls.__PARAMS_CONFIG) - set(data[name])
            if diff:
                errors += f"Config {name} need this values: {', '.join(diff)}\n"
        if errors:
            raise ExceptionCLIValidateConfig(f"Need these values in config file:\n {errors}")
        # else:
        #     self.__data[self.__SECRET_HASH] = bool(self.__data[self.__SECRET_HASH])

    def __getitem__(self, key: str):
        return self.__data[key]

    @property
    def status(self) -> bool:
        return bool(self.__data)

    @property
    def key_id(self) -> str:
        return self.__data[self.__KEY_ID]

    @property
    def access_key(self) -> str:
        return self.__data[self.__ACCESS_KEY]

    @property
    def userpool_id(self) -> str:
        return self.__data[self.__USERPOOL_ID]

    @property
    def app_client_id(self) -> str:
        return self.__data[self.__APP_CLIENT_ID]

    @property
    def app_client_secret(self) -> str:
        return self.__data[self.__APP_CLIENT_SECRET]

    @property
    def secret_hash(self) -> bool:
        return self.__data[self.__SECRET_HASH]

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
