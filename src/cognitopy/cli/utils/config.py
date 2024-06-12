import click
import toml
from pathlib import Path
import os


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
    __PATH_CONFIG = f"{Path.home()}\\.pycognito" if os.name == "nt" else f"{Path.home()}/.pycognito"
    __FILE_CONFIG = "\\config.toml" if os.name == "nt" else "/config.toml"
    __FILE_CONFIG_PATH = f"{__PATH_CONFIG}{__FILE_CONFIG}"

    def __init__(self, config_file: str = None, config_data: dict = None):
        self.__data = {}
        if not config_data and not config_file:
            self.__validate_and_load_config(filepath=self.__FILE_CONFIG_PATH)
        elif not config_data:
            self.__validate_and_load_config(filepath=config_file)
            self.__save_config()
        else:
            self.__write_config(filepath=config_file, config=config_data)
            self.__save_config()

    def __save_config(self) -> None:
        if not os.path.exists(self.__PATH_CONFIG):
            os.mkdir(self.__PATH_CONFIG)
        with open(self.__FILE_CONFIG_PATH, "w+") as f:
            toml.dump(self.__data, f)

    def __validate_and_load_config(self, filepath: str) -> None:
        errors = []
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
            click.echo(f"Need this values in config file {', '.join(errors)}")
            self.__data = {}
        else:
            self.__data[self.__COGNITO][self.__SECRET_HASH] = bool(self.__data[self.__COGNITO][self.__SECRET_HASH])

    def __write_config(self, filepath: str, config: dict) -> None:
        with open(filepath, "w") as f:
            toml.dump(config, f)
        self.__validate_and_load_config(filepath=filepath)

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
            click.echo("Need configurate cognito, run command init before running this command.")
            return None
        else:
            os.environ["AWS_ACCESS_KEY_ID"] = config.key_id
            os.environ["AWS_SECRET_ACCESS_KEY"] = config.access_key
            return config
