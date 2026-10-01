from pathlib import Path


def pytest_configure(config):
    tools_dir = Path(__file__).resolve().parent.parent / "tools"
    csv_dir = Path(__file__).resolve().parent / "files" / "csv"

    from sigma.validators.sigmahq.data import (
        data_atomic_red_team,
        data_filename,
        data_taxonomy,
        data_windows_eventid,
        data_windows_provider,
    )

    data_windows_eventid.set_url(str(tools_dir / "sigmahq_windows_eventid.json"))
    data_windows_provider.set_url(str(tools_dir / "sigmahq_windows_provider.json"))
    data_filename.set_url(str(tools_dir / "sigmahq_filename.json"))
    data_taxonomy.set_url(str(tools_dir / "sigmahq_taxonomy.json"))
    data_atomic_red_team.set_url(str(csv_dir / "sigmahq_atomic_red_team.csv"))
