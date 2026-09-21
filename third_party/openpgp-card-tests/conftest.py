import pytest
from card_reader import get_ccid_device
from openpgp_card import OpenPGP_Card

def pytest_addoption(parser):
    parser.addoption("--reader", dest="reader", type=str, action="store",
                     default="gnuk", help="specify reader: gnuk or gemalto")

@pytest.fixture(scope="session")
def card():
    print()
    print("Test start!")
    reader = get_ccid_device()
    card = OpenPGP_Card(reader)
    # Measured on a real YubiKey 5.7.4 (serial 37365093) on 2026-09-08: PUT DATA
    # F9 adopts the DO's hashes (VERIFY 81 with the hash -> 9000), the gnuk flow's
    # CHANGE with the raw old password -> 6982 with PW1 3->2, and an empty body ->
    # 6A80. RS-Key answers the same, so the suite's own carve-out applies here.
    card.kdf_moves_references = True
    card.cmd_select_openpgp()
    yield card
    del card
    reader.ccid_power_off()
