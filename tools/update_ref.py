# Version 0.3.2
# Author: frack113
# Date: 2025/08/03


from sys import stderr, stdout
from pprint import pformat
import sys


from sigma.validators.sigmahq.config import ConfigHQ


def write_sigmahq_data_py(url: str, output_path="sigma/validators/sigmahq/data/sigmahq_data.py"):
    config = ConfigHQ(url)

    if config.taxonomy_version == "0.0.0":
        print("No sigmahq data found. Please check the URL or the local files.", file=stderr)
        sys.exit(1)

    with open(output_path, "wt", encoding="utf-8", newline="") as file:
        print("from typing import Dict, List", file=file)
        print("from sigma.rule import SigmaLogSource", file=file)
        print("from typing import Optional", file=file)
        print(f'\nfile_pattern_version: str = "{config.filename_version}"', file=file)
        print(
            "ref_sigmahq_logsource_filepattern: Dict[SigmaLogSource, str] = "
            + pformat(config.sigmahq_logsource_filepattern, indent=4, sort_dicts=False),
            file=file,
        )
        print(f'\ntaxonomy_version: str = "{config.taxonomy_version}"', file=file)
        print(
            "ref_sigmahq_fieldsname: Dict[SigmaLogSource, List[str]] = "
            + pformat(config.sigma_fieldsname, indent=4, sort_dicts=False),
            file=file,
        )
        print(
            "ref_sigmahq_redundant_field: Dict[SigmaLogSource, List[str]]= "
            + pformat(config.sigmahq_redundant_fields, indent=4, sort_dicts=False, width=200),
            file=file,
        )
        print(
            "ref_sigmahq_logsource_definition: Dict[SigmaLogSource, Optional[str]] = "
            + pformat(config.sigmahq_logsource_definition, indent=4, sort_dicts=False, width=200),
            file=file,
        )
        print(f'\nwindows_version: str = "{config.windows_version}"', file=file)
        print(
            "ref_windows_provider_name: Dict[SigmaLogSource, List[str]] = "
            + pformat(config.windows_provider_name, indent=4, sort_dicts=False),
            file=file,
        )
        print(
            "ref_windows_no_eventid: List[str] = "
            + pformat(config.windows_no_eventid, indent=4, sort_dicts=False),
            file=file,
        )


def main():
    if len(sys.argv) < 2:
        print("Usage: python update_ref.py <url>", file=stderr)
        sys.exit(1)
    file_url = sys.argv[1]
    print(f"Input URL: {file_url}")
    write_sigmahq_data_py(url=file_url)
    print("sigmahq data files have been processed and sigmahq_data.py has been generated.")


if __name__ == "__main__":
    main()
