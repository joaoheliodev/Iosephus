from app.dominio import integridade, severidade_alerta, sha256, transicao_valida


def test_sha256_conhecido():
    assert sha256("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_transicoes():
    assert transicao_valida("ABERTO", "EM_ANALISE")
    assert transicao_valida("EM_ANALISE", "ENCERRADO")          # falso positivo
    assert not transicao_valida("CONTIDO", "ABERTO")            # nunca volta
    assert not transicao_valida("ENCERRADO", "ENCERRADO")
    assert not transicao_valida("ABERTO", "INVENTADO")


def test_severidade_com_ioc():
    assert severidade_alerta("ALTA", True) == "CRITICA"
    assert severidade_alerta("ALTA", False) == "ALTA"


def test_integridade():
    h = sha256("log original")
    assert integridade(h, {"bruto": "log original"}) == "INTEGRA"
    assert integridade(h, {"bruto": "log alterado"}) == "ADULTERADA"
    assert integridade(h, None) == "AUSENTE"
