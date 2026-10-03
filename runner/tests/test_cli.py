import json
import sys

import pytest

from runner.cli import main,settings_from,SettingsError


@pytest.mark.parametrize('command',['register','run','collect','doctor','scan'])
def test_missing_settings_explain_enrollment_without_traceback(tmp_path,monkeypatch,capsys,command):
    args=['sentinel',command,'--config',str(tmp_path/'missing.json')]
    if command=='register':args+=['--alias','WalletAce','--path',str(tmp_path)]
    if command=='scan':args+=['--path',str(tmp_path)]
    if command=='collect':args+=['--project','example','--log',str(tmp_path/'app.jsonl')]
    monkeypatch.setattr(sys,'argv',args)
    with pytest.raises(SystemExit) as error:main()
    assert error.value.code==2
    output=capsys.readouterr().err
    assert 'Private runners' in output and 'full path with --config' in output
    assert 'Traceback' not in output
    assert not (tmp_path/'missing.json').exists()


@pytest.mark.parametrize('content',['{"token":"secret-fixture",broken','[]','{"roots":[]}','{"roots":{"app":42}}'])
def test_invalid_settings_do_not_echo_credentials(tmp_path,content):
    config=tmp_path/'settings.json';config.write_text(content,encoding='utf-8')
    with pytest.raises(SettingsError) as error:settings_from(config)
    assert 'secret-fixture' not in str(error.value)


def test_register_preserves_credential_and_existing_roots(tmp_path,monkeypatch,capsys):
    config=tmp_path/'settings.json';root=tmp_path/'project';root.mkdir()
    settings={'api_url':'http://127.0.0.1:3000','token':'secret-fixture','roots':{'existing':str(tmp_path)},'allowed_targets':[]}
    config.write_text(json.dumps(settings),encoding='utf-8-sig')
    monkeypatch.setattr(sys,'argv',['sentinel','register','--config',str(config),'--alias','WalletAce','--path',str(root)])
    assert main()==0
    updated=json.loads(config.read_text(encoding='utf-8'))
    assert updated=={**settings,'roots':{**settings['roots'],'WalletAce':str(root.resolve())}}
    assert 'secret-fixture' not in capsys.readouterr().out


def test_missing_source_does_not_modify_settings(tmp_path,monkeypatch,capsys):
    config=tmp_path/'settings.json';config.write_text('{"roots":{}}',encoding='utf-8')
    before=config.read_bytes()
    monkeypatch.setattr(sys,'argv',['sentinel','register','--config',str(config),'--alias','WalletAce','--path',str(tmp_path/'missing')])
    with pytest.raises(SystemExit) as error:main()
    assert error.value.code==2 and 'Check --path' in capsys.readouterr().err
    assert config.read_bytes()==before
