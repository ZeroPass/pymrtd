
import pytest
from pymrtd.ef.base import ElementaryFile
from pymrtd.ef.dg import DataGroup, DataGroupNumber

def test_dg_number():
    dgn = DataGroupNumber(1)
    assert dgn.value  == 1
    assert dgn.native == 'EF.DG1'
    assert dgn == 1
    assert dgn == DataGroupNumber(1)
    assert dgn != 2
    assert dgn != DataGroupNumber(2)

    dgn = DataGroupNumber(2)
    assert dgn.value  == 2
    assert dgn.native == 'EF.DG2'
    assert dgn == 2
    assert dgn == DataGroupNumber(2)
    assert dgn != 1
    assert dgn != DataGroupNumber(1)

    dgn = DataGroupNumber(21) # EF.DG2 ASN1 tag is 21
    assert dgn.value  == 2
    assert dgn.native == 'EF.DG2'
    assert dgn == 2
    assert dgn == DataGroupNumber(2)
    assert dgn != 1
    assert dgn != DataGroupNumber(1)

    dgn = DataGroupNumber(3)
    assert dgn.value  == 3
    assert dgn.native == 'EF.DG3'
    assert dgn == 3
    assert dgn == DataGroupNumber(3)
    assert dgn != 1
    assert dgn != DataGroupNumber(1)

    dgn = DataGroupNumber(4)
    assert dgn.value  == 4
    assert dgn.native == 'EF.DG4'
    assert dgn == 4
    assert dgn == DataGroupNumber(4)
    assert dgn != 1
    assert dgn != DataGroupNumber(1)

    dgn = DataGroupNumber(22) # EF.DG4 ASN1 tag is 22
    assert dgn.value  == 4
    assert dgn.native == 'EF.DG4'
    assert dgn == 4
    assert dgn == DataGroupNumber(4)
    assert dgn != 1
    assert dgn != DataGroupNumber(1)

    dgn = DataGroupNumber(5)
    assert dgn.value  == 5
    assert dgn.native == 'EF.DG5'
    assert dgn == 5
    assert dgn == DataGroupNumber(5)
    assert dgn != 1
    assert dgn != DataGroupNumber(1)

    dgn = DataGroupNumber(6)
    assert dgn.value  == 6
    assert dgn.native == 'EF.DG6'
    assert dgn == 6
    assert dgn == DataGroupNumber(6)
    assert dgn != 1
    assert dgn != DataGroupNumber(1)

    dgn = DataGroupNumber(7)
    assert dgn.value  == 7
    assert dgn.native == 'EF.DG7'
    assert dgn == 7
    assert dgn == DataGroupNumber(7)
    assert dgn != 1
    assert dgn != DataGroupNumber(1)

    dgn = DataGroupNumber(8)
    assert dgn.value  == 8
    assert dgn.native == 'EF.DG8'
    assert dgn == 8
    assert dgn == DataGroupNumber(8)
    assert dgn != 1
    assert dgn != DataGroupNumber(1)

    dgn = DataGroupNumber(9)
    assert dgn.value  == 9
    assert dgn.native == 'EF.DG9'
    assert dgn == 9
    assert dgn == DataGroupNumber(9)
    assert dgn != 1
    assert dgn != DataGroupNumber(1)

    dgn = DataGroupNumber(10)
    assert dgn.value  == 10
    assert dgn.native == 'EF.DG10'
    assert dgn == 10
    assert dgn == DataGroupNumber(10)
    assert dgn != 1
    assert dgn != DataGroupNumber(1)

    dgn = DataGroupNumber(11)
    assert dgn.value  == 11
    assert dgn.native == 'EF.DG11'
    assert dgn == 11
    assert dgn == DataGroupNumber(11)
    assert dgn != 1
    assert dgn != DataGroupNumber(1)

    dgn = DataGroupNumber(12)
    assert dgn.value  == 12
    assert dgn.native == 'EF.DG12'
    assert dgn == 12
    assert dgn == DataGroupNumber(12)
    assert dgn != 1
    assert dgn != DataGroupNumber(1)

    dgn = DataGroupNumber(13)
    assert dgn.value  == 13
    assert dgn.native == 'EF.DG13'
    assert dgn == 13
    assert dgn == DataGroupNumber(13)
    assert dgn != 1
    assert dgn != DataGroupNumber(1)

    dgn = DataGroupNumber(14)
    assert dgn.value  == 14
    assert dgn.native == 'EF.DG14'
    assert dgn == 14
    assert dgn == DataGroupNumber(14)
    assert dgn != 1
    assert dgn != DataGroupNumber(1)

    dgn = DataGroupNumber(15)
    assert dgn.value  == 15
    assert dgn.native == 'EF.DG15'
    assert dgn == 15
    assert dgn == DataGroupNumber(15)
    assert dgn != 1
    assert dgn != DataGroupNumber(1)

    dgn = DataGroupNumber(16)
    assert dgn.value  == 16
    assert dgn.native == 'EF.DG16'
    assert dgn == 16
    assert dgn == DataGroupNumber(16)
    assert dgn != 1
    assert dgn != DataGroupNumber(1)

    # Fuzz tests
    with pytest.raises(ValueError, match="Invalid data group number"):
        dgn = DataGroupNumber(17)
    with pytest.raises(ValueError, match="Invalid data group number"):
        dgn = DataGroupNumber(0)
    with pytest.raises(ValueError, match="Invalid data group number"):
        dgn = DataGroupNumber(-1)

@pytest.mark.depends(on=['test_dg_number'])
def test_dg_base():
    assert issubclass(DataGroup, ElementaryFile)
    dg1 = DataGroup.load(bytes.fromhex('6100'))
    assert dg1.number == DataGroupNumber(1)
    dg2 = DataGroup.load(bytes.fromhex('7500'))
    assert dg2.number == DataGroupNumber(2)
    with pytest.raises(ValueError, match="Invalid data group number"):
        dgInv = DataGroup.load(bytes.fromhex('6000'))
        dgInv.number
