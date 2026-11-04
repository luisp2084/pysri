"""Utilidades XML con parseo endurecido (sin entidades externas, DTD ni red)."""
from typing import Any

from lxml import etree

from pysri.exceptions import InvalidXMLError

MAX_XML_BYTES = 2 * 1024 * 1024


def safe_parser() -> etree.XMLParser:
    return etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        dtd_validation=False,
        huge_tree=False,
        remove_comments=False,
        remove_pis=False,
    )


def parse_xml(data: bytes | str, max_bytes: int = MAX_XML_BYTES) -> etree._Element:
    """Parsea XML de forma segura; rechaza DOCTYPE (XXE / billion laughs)."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    if len(data) > max_bytes:
        raise InvalidXMLError("El XML excede el tamaño máximo permitido")
    try:
        root = etree.fromstring(data, parser=safe_parser())
    except etree.XMLSyntaxError as exc:
        raise InvalidXMLError(f"XML mal formado: {exc}") from None
    if root.getroottree().docinfo.doctype:
        raise InvalidXMLError("No se permiten declaraciones DOCTYPE")
    return root


def local_name(element: etree._Element) -> str:
    return etree.QName(element).localname


def _element_to_value(element: etree._Element) -> Any:
    children = [c for c in element if isinstance(c.tag, str)]
    if not children:
        if element.attrib:
            data = dict(element.attrib)
            if element.text and element.text.strip():
                data["#text"] = element.text.strip()
            return data
        return element.text.strip() if element.text else None
    result: dict[str, Any] = dict(element.attrib)
    for child in children:
        key = local_name(child)
        value = _element_to_value(child)
        if key in result:
            if not isinstance(result[key], list):
                result[key] = [result[key]]
            result[key].append(value)
        else:
            result[key] = value
    return result


def xml_to_dict(xml: bytes | str) -> dict[str, Any]:
    """Convierte un XML a dict ``{tag_raiz: contenido}``. Las etiquetas repetidas se agrupan en listas."""
    root = parse_xml(xml)
    return {local_name(root): _element_to_value(root)}


def _build(parent: etree._Element, key: str, value: Any) -> None:
    if isinstance(value, list):
        for item in value:
            _build(parent, key, item)
        return
    child = etree.SubElement(parent, key)
    if isinstance(value, dict):
        for k, v in value.items():
            if k.startswith("@"):
                child.set(k[1:], str(v))
            elif k == "#text":
                child.text = str(v)
            elif v is not None:
                _build(child, k, v)
    elif value is not None:
        child.text = str(value)


def dict_to_xml(dictionary: dict[str, Any], root_tag: str | None = None) -> bytes:
    """Convierte un dict a XML.

    Si ``root_tag`` es None, el dict debe tener una única clave que será la raíz.
    Las claves que empiezan con ``@`` se convierten en atributos y ``#text`` en texto.
    """
    if root_tag is None:
        if len(dictionary) != 1:
            raise ValueError("El dict debe tener una sola clave raíz o indicar root_tag")
        root_tag, content = next(iter(dictionary.items()))
    else:
        content = dictionary
    holder = etree.Element("holder")
    _build(holder, root_tag, content)
    return serialize(holder[0])


def serialize(element: etree._Element) -> bytes:
    """Serializa a UTF-8 con declaración XML estándar (comillas dobles)."""
    body = etree.tostring(element, encoding="UTF-8", xml_declaration=False)
    return b'<?xml version="1.0" encoding="UTF-8"?>\n' + body
