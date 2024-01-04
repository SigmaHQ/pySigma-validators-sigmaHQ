from typing import ClassVar, Dict, List
from pathlib import Path
import json

from sigma.rule import SigmaLogSource



class ConfigHq:
    title_lengh = 10
    allowed_lowercase_words:List[str] = []
    sigmahq_invalid_trademark:List[str] = []
    sigmahq_fp_banned_word:List[str] = []
    sigmahq_fp_typo_word:List[str] = []
    sigmahq_link_in_description:List[str] = []
    sigmahq_logsource_cast: Dict[SigmaLogSource, List[str]] = {}
    sigmahq_logsource_unicast: Dict[SigmaLogSource, List[str]] = {}
    sigmahq_logsource_list: Dict[SigmaLogSource, str] = {}
    sigmahq_logsource_prefix: Dict[SigmaLogSource, str] = {}
    sigmahq_product_prefix: Dict[str, str] = {}


    def __init__(self) -> None:
        # basic parameter
        if Path("./tests/config_HQ.json").exists():
            path_json = Path("./tests/config_HQ.json")
        else:
            path_json = Path(__file__).parent.resolve() / Path("data/config_HQ.json")
        with path_json.open("r") as config_file:
            config = json.load(config_file)

        self.title_lengh = config.get("title_lengh")
        self.allowed_lowercase_words = config.get("allowed_lowercase_words")
        self.sigmahq_invalid_trademark = config.get("sigmahq_invalid_trademark")
        self.sigmahq_fp_banned_word = config.get("sigmahq_fp_banned_word")
        self.sigmahq_fp_typo_word = config.get("sigmahq_fp_typo_word")
        self.sigmahq_link_in_description = config.get("sigmahq_link_in_description")

        # Field name cast by logsource
        if Path("./tests/sigmahq_product_cast.json").exists():
            path_json = Path("./tests/sigmahq_product_cast.json")
        else:
            path_json = Path(__file__).parent.resolve() / Path(
                "data/sigmahq_product_cast.json"
            )
        with path_json.open("r") as file:
            logdata = json.load(file)
            for logsource in logdata.values():
                field = logsource["field"]
                category = logsource["category"] if logsource["category"] != "" else None
                product = logsource["product"] if logsource["product"] != "" else None
                service = logsource["service"] if logsource["service"] != "" else None
                self.sigmahq_logsource_cast[SigmaLogSource(category, product, service)] = field

                if "Hashes" in field or "Hash" in field:
                    field.extend(["Imphash", "md5", "sha1", "sha256"])
                if product == "windows":
                    field.extend(["EventID", "Provider_Name"])

                self.sigmahq_logsource_unicast[SigmaLogSource(category, product, service)] = [
                    x.lower() for x in field
                ]

        # Valid logsource list
        if Path("./tests/sigmahq_logsource_valid.json").exists():
            path_json = Path("./tests/sigmahq_logsource_valid.json")
        else:
            path_json = Path(__file__).parent.resolve() / Path(
                "data/sigmahq_logsource_valid.json"
            )

        with path_json.open("r") as file:
            logdata = json.load(file)
            for logsource in logdata["logsource"]:
                category = (
                    logsource["category"] if logsource["category"] != "" else None
                )
                product = logsource["product"] if logsource["product"] != "" else None
                service = logsource["service"] if logsource["service"] != "" else None
                self.sigmahq_logsource_list[SigmaLogSource(category, product, service)] = ""

        # SigmaHQ filename
        if Path("./tests/sigmahq_logsource_prefix.json").exists():
            path_json = Path("./tests/sigmahq_logsource_prefix.json")
        else:
            path_json = Path(__file__).parent.resolve() / Path(
                "data/sigmahq_logsource_prefix.json"
            )

        with path_json.open("r") as file:
            logdata = json.load(file)
            for logsource in logdata.values():
                prefix = logsource["prefix"]
                category = (
                    logsource["category"] if logsource["category"] != "" else None
                )
                product = logsource["product"] if logsource["product"] != "" else None
                service = logsource["service"] if logsource["service"] != "" else None
                self.sigmahq_logsource_prefix[
                    SigmaLogSource(category, product, service)
                ] = prefix

        if Path("./tests/sigmahq_product_prefix.json").exists():
            path_json = Path("./tests/sigmahq_product_prefix.json")
        else:
            path_json = Path(__file__).parent.resolve() / Path(
                "data/sigmahq_product_prefix.json"
            )

        with path_json.open("r") as file:
            logdata = json.load(file)
            for product, prefix in logdata.items():
                self.sigmahq_product_prefix[product] = prefix