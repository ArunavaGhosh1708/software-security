import pytest
from runner.adapters import checkstyle_report, checkstyle_violation_exit


def report(count):
    error='<error line="2" severity="error" message="Avoid star imports" source="com.puppycrawl.tools.checkstyle.checks.imports.AvoidStarImportCheck"/>'
    return '<checkstyle version="10.21.1"><file name="/src/App.java">'+error*count+'</file></checkstyle>'


@pytest.mark.parametrize('count',[2,3,125,256,257])
def test_violation_count_is_not_a_scanner_crash(count):
    assert checkstyle_violation_exit(report(count),count%256)
    assert not checkstyle_violation_exit(report(count),(count+1)%256)


@pytest.mark.parametrize('raw',[
    '', '<invalid/>', '<checkstyle><exception>Failure</exception></checkstyle>',
    '<!DOCTYPE checkstyle [<!ENTITY x SYSTEM "file:///secret">]><checkstyle>&x;</checkstyle>',
    '<checkstyle><file><error severity="error" source="com.puppycrawl.tools.checkstyle.TreeWalker"/></file></checkstyle>'
])
def test_processing_errors_and_invalid_output_remain_failures(raw):
    assert not checkstyle_violation_exit(raw,2)
    with pytest.raises(ValueError):checkstyle_report(raw)


def test_nonzero_exit_without_violations_remains_failure():
    assert not checkstyle_violation_exit(report(0),2)
    assert not checkstyle_violation_exit(report(2),-9)
