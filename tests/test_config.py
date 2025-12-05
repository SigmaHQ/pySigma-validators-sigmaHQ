import pytest
import json
from pathlib import Path
from unittest.mock import patch, MagicMock
from sigma.validators.sigmahq.config import ConfigHQ, core_logsource, key_logsource
from sigma.rule import SigmaLogSource


def test_core_logsource_function():
    """Test the core_logsource function."""
    # Create a sample logsource
    source = SigmaLogSource(product="windows", category="process_creation", service="svchost")

    # Test core_logsource function
    core_source = core_logsource(source)

    assert core_source.product == "windows"
    assert core_source.category == "process_creation"
    assert core_source.service == "svchost"


def test_key_logsource_function():
    """Test the key_logsource function."""
    # Test with complete logsource dict
    source_dict = {"product": "windows", "category": "process_creation", "service": "svchost"}

    key = key_logsource(source_dict)
    assert key == "windows_process_creation_svchost"

    # Test with missing fields
    source_dict_missing = {"product": None, "category": "process_creation", "service": None}

    key = key_logsource(source_dict_missing)
    assert key == "none_process_creation_none"


def test_config_load_sigma_json_no_taxonomy():
    """Test _load_sigma_json with missing taxonomy to cover lines 92-94."""
    config = ConfigHQ()

    # Mock a scenario where json_dict doesn't have "taxonomy"
    with patch.object(config, "_load_json", return_value={"version": "1.0"}):
        # This should not raise an exception and should return early
        result = config._load_sigma_json()
        assert result is None  # _load_sigma_json returns None


def test_config_load_filename_json_no_pattern():
    """Test _load_filename_json with missing pattern."""
    config = ConfigHQ()

    # Mock a scenario where json_dict doesn't have "pattern"
    with patch.object(config, "_load_json", return_value={"version": "1.0"}):
        result = config._load_filename_json()
        assert result is None


def test_config_load_windows_provider_json_no_keys():
    """Test _load_windows_provider_json with missing keys."""
    config = ConfigHQ()

    # Mock a scenario where json_dict doesn't have required keys
    with patch.object(config, "_load_json", return_value={"version": "1.0"}):
        result = config._load_windows_provider_json()
        assert result is None


def test_config_load_json_remote_success():
    """Test _load_json with remote URL success."""
    config = ConfigHQ("https://example.com/config")

    # Mock requests.get to simulate a successful response
    mock_response = MagicMock()
    mock_response.json.return_value = {"test": "data"}
    mock_response.raise_for_status.return_value = None

    with patch("requests.get", return_value=mock_response):
        result = config._load_json("test.json")
        assert result == {"test": "data"}


def test_config_load_json_remote_error():
    """Test _load_json with remote URL error."""
    config = ConfigHQ("https://example.com/config")

    # Mock requests.get to simulate an exception
    with patch("requests.get", side_effect=Exception("Network error")):
        result = config._load_json("test.json")
        assert result is None


def test_config_load_json_local_file_error():
    """Test _load_json with local file error."""
    config = ConfigHQ()

    # Mock config_dir to simulate a local directory
    config.config_dir = Path("non_existent_directory")

    result = config._load_json("test.json")
    assert result is None


def test_config_with_none_data_place():
    """Test ConfigHQ initialization with None data_place."""
    config = ConfigHQ(None)

    # Should have loaded default reference data
    assert hasattr(config, "taxonomy_version")
    assert hasattr(config, "sigma_fieldsname")
    assert hasattr(config, "sigmahq_redundant_fields")
    assert hasattr(config, "sigmahq_logsource_definition")
    assert hasattr(config, "filename_version")
    assert hasattr(config, "sigmahq_logsource_filepattern")
    assert hasattr(config, "windows_version")
    assert hasattr(config, "windows_provider_name")
    assert hasattr(config, "windows_no_eventid")


def test_config_with_empty_string_data_place():
    """Test ConfigHQ initialization with empty string data_place."""
    config = ConfigHQ("")

    # Should have loaded default reference data
    assert hasattr(config, "taxonomy_version")
    assert hasattr(config, "sigma_fieldsname")
    assert hasattr(config, "sigmahq_redundant_fields")
    assert hasattr(config, "sigmahq_logsource_definition")
    assert hasattr(config, "filename_version")
    assert hasattr(config, "sigmahq_logsource_filepattern")
    assert hasattr(config, "windows_version")
    assert hasattr(config, "windows_provider_name")
    assert hasattr(config, "windows_no_eventid")


def test_config_load_sigma_json_success():
    """Test _load_sigma_json with valid data."""
    config = ConfigHQ()

    # Mock a scenario where json_dict has taxonomy
    mock_taxonomy_data = {
        "version": "1.0",
        "taxonomy": {
            "test_key": {
                "logsource": {
                    "product": "windows",
                    "category": "process_creation",
                    "service": "svchost",
                },
                "field": {
                    "native": ["field1", "field2"],
                    "custom": ["field3"],
                    "redundant": ["field4"],
                },
            }
        },
    }

    with patch.object(config, "_load_json", return_value=mock_taxonomy_data):
        config._load_sigma_json()

        # Check that data was loaded correctly
        assert config.taxonomy_version == "1.0"
        assert isinstance(config.sigma_fieldsname, dict)
        assert isinstance(config.sigmahq_redundant_fields, dict)
        assert isinstance(config.sigmahq_logsource_definition, dict)


def test_config_load_filename_json_success():
    """Test _load_filename_json with valid data."""
    config = ConfigHQ()

    # Mock a scenario where json_dict has pattern
    mock_pattern_data = {
        "version": "1.0",
        "pattern": {
            "test_key": {
                "logsource": {
                    "product": "windows",
                    "category": "process_creation",
                    "service": "svchost",
                },
                "prefix": "test_prefix",
            }
        },
    }

    with patch.object(config, "_load_json", return_value=mock_pattern_data):
        config._load_filename_json()

        # Check that data was loaded correctly
        assert config.filename_version == "1.0"
        assert isinstance(config.sigmahq_logsource_filepattern, dict)


def test_config_load_windows_provider_json_success():
    """Test _load_windows_provider_json with valid data."""
    config = ConfigHQ()

    # Mock a scenario where json_dict has category_provider_name and category_no_eventid
    mock_windows_data = {
        "version": "1.0",
        "category_provider_name": {"process_creation": "Microsoft-Windows-Sysmon"},
        "category_no_eventid": ["process_creation"],
    }

    with patch.object(config, "_load_json", return_value=mock_windows_data):
        config._load_windows_provider_json()

        # Check that data was loaded correctly
        assert config.windows_version == "1.0"
        assert isinstance(config.windows_provider_name, dict)
        assert isinstance(config.windows_no_eventid, list)


def test_config_init_with_remote_url():
    """Test ConfigHQ initialization with remote URL."""
    config = ConfigHQ("https://example.com/config")

    assert config.config_url == "https://example.com/config"
    assert config.config_dir is None


def test_config_init_with_local_path():
    """Test ConfigHQ initialization with local path."""
    config = ConfigHQ("/tmp/config")

    assert config.config_dir == Path("/tmp/config")
    assert config.config_url is None


def test_config_init_with_default_local_path():
    """Test ConfigHQ initialization with default local path."""
    # Create a temporary directory for testing
    with patch("pathlib.Path.exists", return_value=True):
        config = ConfigHQ(None)

        assert config.config_dir is not None
        assert config.config_url is None


def test_config_load_sigma_json_empty_taxonomy():
    """Test _load_sigma_json with empty taxonomy."""
    config = ConfigHQ()

    # Mock a scenario where json_dict has empty taxonomy
    with patch.object(config, "_load_json", return_value={"version": "1.0", "taxonomy": {}}):
        config._load_sigma_json()

        # Should not crash and should keep default values
        assert config.taxonomy_version == "1.0"


def test_config_load_filename_json_empty_pattern():
    """Test _load_filename_json with empty pattern."""
    config = ConfigHQ()

    # Mock a scenario where json_dict has empty pattern
    with patch.object(config, "_load_json", return_value={"version": "1.0", "pattern": {}}):
        config._load_filename_json()

        # Should not crash and should keep default values
        assert config.filename_version == "1.0"


def test_config_load_windows_provider_json_empty_data():
    """Test _load_windows_provider_json with empty data."""
    config = ConfigHQ()

    # Mock a scenario where json_dict has no required keys
    with patch.object(config, "_load_json", return_value={"version": "1.0"}):
        # Store original values before loading
        original_version = config.windows_version
        original_provider_name = config.windows_provider_name
        original_no_eventid = config.windows_no_eventid

        config._load_windows_provider_json()

        # Should not crash and should keep original default values
        assert config.windows_version == original_version
        assert config.windows_provider_name == original_provider_name
        assert config.windows_no_eventid == original_no_eventid


def test_config_with_none_data_place_no_local_folder():
    """Test ConfigHQ initialization with None data_place when no local folder exists.
    
    This tests the new default behavior of using DEFAULT_REMOTE_URL when 
    data_place is None and no local folder exists.
    """
    # Mock Path.exists() to return False to simulate no local folder
    with patch("pathlib.Path.exists", return_value=False):
        # Mock requests.get to verify remote loading is attempted
        mock_response = MagicMock()
        mock_response.json.return_value = {"version": "1.0"}
        mock_response.raise_for_status.return_value = None

        with patch("sigma.validators.sigmahq.config.requests.get", return_value=mock_response) as mock_get:
            config = ConfigHQ(None)

            # Verify that config_url is set to DEFAULT_REMOTE_URL
            assert config.config_url == ConfigHQ.DEFAULT_REMOTE_URL
            assert config.config_dir is None

            # Verify that remote loading was attempted with the default URL
            assert mock_get.called
            # Check that all three JSON files were requested from the default URL
            expected_calls = [
                f"{ConfigHQ.DEFAULT_REMOTE_URL}/{ConfigHQ.JSON_NAME_TAXONOMY}",
                f"{ConfigHQ.DEFAULT_REMOTE_URL}/{ConfigHQ.JSON_NAME_FILENAME}",
                f"{ConfigHQ.DEFAULT_REMOTE_URL}/{ConfigHQ.JSON_NAME_WINDOWS_PROVIDER}",
            ]
            actual_urls = [call[0][0] for call in mock_get.call_args_list]
            for expected_url in expected_calls:
                assert expected_url in actual_urls
