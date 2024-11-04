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
    __CURRENT = "current"
    __PROJECT = "project"

    def __init__(self, file_path: str = __FILE_CONFIG_PATH):
        with open(file_path, "r") as f:
            data = toml.load(f)
        self.validate_config(config=data)
        if self.__CURRENT not in data.keys():
            raise ExceptionCLIValidateConfig("Need set current project")
        self.__name = data[self.__CURRENT][self.__PROJECT]
        self.__data = data[self.__name]
        self.__data[self.__SECRET_HASH] = bool(self.__data[self.__SECRET_HASH])
        key_id = self.__data[self.__KEY_ID]
        access_key = self.__data[self.__ACCESS_KEY]
        if "AWS_ACCESS_KEY_ID" not in os.environ or os.environ["AWS_ACCESS_KEY_ID"] != key_id:
            os.environ["AWS_ACCESS_KEY_ID"] = key_id
        if "AWS_SECRET_ACCESS_KEY" not in os.environ or os.environ["AWS_SECRET_ACCESS_KEY"] != access_key:
            os.environ["AWS_SECRET_ACCESS_KEY"] = access_key

    @classmethod
    def save_config(cls, data_config) -> None:
        if not os.path.exists(cls.__PATH_CONFIG):
            os.mkdir(cls.__PATH_CONFIG)
        with open(cls.__FILE_CONFIG_PATH, "a") as f:
            toml.dump(data_config, f)
        with open(cls.__FILE_CONFIG_PATH, "r") as f:
            data = toml.load(f)
        if cls.__CURRENT not in data.keys():
            cls.set_name()

    @classmethod
    def validate_config_file(cls, filepath: str) -> None:
        data_config = {}
        with open(filepath, "r") as f:
            config = toml.load(f)
        if os.path.exists(cls.__FILE_CONFIG_PATH):
            with open(cls.__FILE_CONFIG_PATH, "r") as f:
                data_config = toml.load(f)
        cls.validate_config(config=config, data_config=data_config)

    @classmethod
    def validate_config(cls, config: dict, data_config: dict = {}) -> None:
        errors = ""
        names = [name for name in config.keys() if name != cls.__CURRENT]
        for name in names:
            if name in data_config.keys():
                raise ExceptionCLIValidateConfig(f"This name config {name} already exists in config file")
            if not isinstance(config[name], dict):
                raise ExceptionCLIValidateConfig(f"Need these values {', '.join(cls.__PARAMS_CONFIG)} into in name "
                                                 "config")
            diff = set(cls.__PARAMS_CONFIG) - set(config[name])
            if diff:
                errors += f"Config {name} need this values: {', '.join(diff)}\n"
        if errors:
            raise ExceptionCLIValidateConfig(f"Need these values in config file: \n {errors}")

    @classmethod
    def get_config(cls):
        with open(cls.__FILE_CONFIG_PATH, "r") as f:
            return toml.load(f)

    @classmethod
    def set_name(cls, name: str = None):
        with open(cls.__FILE_CONFIG_PATH, "r") as f:
            data = toml.load(f)
        if not name:
            name = [name for name in data.keys() if name != cls.__CURRENT][0]
        if cls.__CURRENT not in data.keys():
            data[cls.__CURRENT] = {cls.__PROJECT: name}
        else:
            data[cls.__CURRENT][cls.__PROJECT] = name
        with open(cls.__FILE_CONFIG_PATH, "w") as f:
            toml.dump(data, f)

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

    @property
    def name(self) -> str:
        return self.__name
