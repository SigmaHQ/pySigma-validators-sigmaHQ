# Version 0.3.0
# Author: frack113
# Date: 2025/06/13


from sys import stderr, stdout
from pprint import pformat
import sys


from sigma.validators.sigmahq.config import (
    process_sigmahq_filename,
    process_sigma_json,
    process_sigmahq_windows_validator,
)


def write_sigmahq_data_py(url, output_path="sigma/validators/sigmahq/sigmahq_data.py"):
    filename_version, filename_info = process_sigmahq_filename(url)
    taxonomy_version, taxonomy_info, taxonomy_definition, taxonomy_unneeded = process_sigma_json(
        url
    )
    windows_version, windows_provider_name, windows_no_eventid = process_sigmahq_windows_validator(
        url
    )
    with open(output_path, "wt", encoding="utf-8", newline="") as file:
        print("from typing import Dict, List", file=file)
        print("from sigma.rule import SigmaLogSource", file=file)
        print("from typing import Optional", file=file)
        print(f'\nfile_pattern_version: str = "{filename_version}"', file=file)
        print(
            "ref_sigmahq_logsource_filepattern: Dict[SigmaLogSource, str] = "
            + pformat(filename_info, indent=4, sort_dicts=False),
            file=file,
        )
        print(f'\ntaxonomy_version: str = "{taxonomy_version}"', file=file)
        print(
            "ref_sigmahq_fieldsname: Dict[SigmaLogSource, List[str]] = "
            + pformat(taxonomy_info, indent=4, sort_dicts=False),
            file=file,
        )
        print(
            "ref_sigmahq_unneededfield: Dict[SigmaLogSource, List[str]]= "
            + pformat(taxonomy_unneeded, indent=4, sort_dicts=False, width=200),
            file=file,
        )
        print(
            "ref_sigmahq_logsource_definition: Dict[SigmaLogSource, Optional[str]] = "
            + pformat(taxonomy_definition, indent=4, sort_dicts=False, width=200),
            file=file,
        )
        print(f'\nwindows_version: str = "{windows_version}"', file=file)
        print(
            "ref_windows_provider_name: Dict[SigmaLogSource, List[str]] = "
            + pformat(windows_provider_name, indent=4, sort_dicts=False),
            file=file,
        )
        print(
            "ref_windows_no_eventid: List[str] = "
            + pformat(windows_no_eventid, indent=4, sort_dicts=False),
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
