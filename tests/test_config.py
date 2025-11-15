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
    source_dict = {
        "product": "windows",
        "category": "process_creation", 
        "service": "svchost"
    }
    
    key = key_logsource(source_dict)
    assert key == "windows_process_creation_svchost"
    
    # Test with missing fields
    source_dict_missing = {
        "product": None,
        "category": "process_creation",
        "service": None
    }
    
    key = key_logsource(source_dict_missing)
    assert key == "none_process_creation_none"


def test_config_load_sigma_json_no_taxonomy():
    """Test _load_sigma_json with missing taxonomy to cover lines 92-94."""
    config = ConfigHQ()
    
    # Mock a scenario where json_dict doesn't have "taxonomy"
    with patch.object(config, '_load_json', return_value={"version": "1.0"}):
        # This should not raise an exception and should return early
        result = config._load_sigma_json()
        assert result is None  # _load_sigma_json returns None


def test_config_load_filename_json_no_pattern():
    """Test _load_filename_json with missing pattern."""
    config = ConfigHQ()
    
    # Mock a scenario where json_dict doesn't have "pattern"
    with patch.object(config, '_load_json', return_value={"version": "1.0"}):
        result = config._load_filename_json()
        assert result is None


def test_config_load_windows_provider_json_no_keys():
    """Test _load_windows_provider_json with missing keys."""
    config = ConfigHQ()
    
    # Mock a scenario where json_dict doesn't have required keys
    with patch.object(config, '_load_json', return_value={"version": "1.0"}):
        result = config._load_windows_provider_json()
        assert result is None


def test_config_load_json_remote_success():
    """Test _load_json with remote URL success."""
    config = ConfigHQ("https://example.com/config")
    
    # Mock requests.get to simulate a successful response
    mock_response = MagicMock()
    mock_response.json.return_value = {"test": "data"}
    mock_response.raise_for_status.return_value = None
    
    with patch('requests.get', return_value=mock_response):
        result = config._load_json("test.json")
        assert result == {"test": "data"}


def test_config_load_json_remote_error():
    """Test _load_json with remote URL error."""
    config = ConfigHQ("https://example.com/config")
    
    # Mock requests.get to simulate an exception
    with patch('requests.get', side_effect=Exception("Network error")):
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
    assert hasattr(config, 'taxonomy_version')
    assert hasattr(config, 'sigma_fieldsname')
    assert hasattr(config, 'sigmahq_redundant_fields')
    assert hasattr(config, 'sigmahq_logsource_definition')
    assert hasattr(config, 'filename_version')
    assert hasattr(config, 'sigmahq_logsource_filepattern')
    assert hasattr(config, 'windows_version')
    assert hasattr(config, 'windows_provider_name')
    assert hasattr(config, 'windows_no_eventid')


def test_config_with_empty_string_data_place():
    """Test ConfigHQ initialization with empty string data_place."""
    config = ConfigHQ("")
    
    # Should have loaded default reference data
    assert hasattr(config, 'taxonomy_version')
    assert hasattr(config, 'sigma_fieldsname')
    assert hasattr(config, 'sigmahq_redundant_fields')
    assert hasattr(config, 'sigmahq_logsource_definition')
    assert hasattr(config, 'filename_version')
    assert hasattr(config, 'sigmahq_logsource_filepattern')
    assert hasattr(config, 'windows_version')
    assert hasattr(config, 'windows_provider_name')
    assert hasattr(config, 'windows_no_eventid')