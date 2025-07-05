import unittest
from unittest.mock import patch, mock_open
from Shield import scan_file

class TestQuickShieldAntivirus(unittest.TestCase):

    @patch("os.path.exists", return_value=True)  # Mock file existence check
    @patch("builtins.open", new_callable=mock_open, read_data=b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    def test_eicar_threat_detection(self, mock_file, mock_exists):
        """Test EICAR threat detection by providing test file data."""
        file_path = r"C:\Users\singh\Desktop\Threats\EICAR_2.txt"
        result = scan_file(file_path=file_path)
        # Ensure the function detects the EICAR threat
        self.assertIn("Threat detected", result)

    @patch("os.path.exists", return_value=True)  # Mock file existence check
    @patch("builtins.open", new_callable=mock_open, read_data=b"clean content")
    def test_no_threats(self, mock_file, mock_exists):
        """Test scanning a benign file."""
        file_path = r"C:\Users\singh\Desktop\clean.txt"
        result = scan_file(file_path=file_path)
        # Ensure the function correctly identifies no threats
        self.assertIn("No Threat detected", result)



if __name__ == "__main__":
    unittest.main()


#Using pywinsandbox