from pathlib import Path


def pytest_configure(config):
    tools_dir = Path(__file__).resolve().parent.parent / "tools"

    from sigma.data import mitre_attack

    from sigma.validators.sigmahq.data import (
        data_filename,
        data_taxonomy,
        data_windows_eventid,
        data_windows_provider,
    )

    data_windows_eventid.set_url(str(tools_dir / "sigmahq_windows_eventid.json"))
    data_windows_provider.set_url(str(tools_dir / "sigmahq_windows_provider.json"))
    data_filename.set_url(str(tools_dir / "sigmahq_filename.json"))
    data_taxonomy.set_url(str(tools_dir / "sigmahq_taxonomy.json"))
    mitre_attack.set_url(str(tools_dir / "mitre_attack_enterprise.json"))
