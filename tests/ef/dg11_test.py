import pytest

from pymrtd import ef


@pytest.mark.depends(
    on=[
        "tests/ef/ef_base_test.py::test_ef_base",
        "tests/ef/dg_base_test.py::test_dg_base",
    ]
)
def test_dg11():
    assert issubclass(ef.DG11, ef.DataGroup)

    tv_dg11 = bytes.fromhex(
        "6B305C065F0E5F2B5F115F0E0C546573743C3C5465737465725F2B0831393730313230315F110B4E6F727468616D70746F6E"
    )
    dg11 = ef.DG11.load(tv_dg11)
    assert dg11.dump() == tv_dg11
    assert dg11.personal_info.full_name == "Test<<Tester"
    assert dg11.personal_info.place_of_birth == "Northampton"
