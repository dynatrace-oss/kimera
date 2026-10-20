from kubernetes.client import V1ObjectMeta

from kimera.container.core.k8s_meta import meta_name


def test_meta_name_returns_name() -> None:
    assert meta_name(V1ObjectMeta(name="my-deployment")) == "my-deployment"


def test_meta_name_handles_none_metadata() -> None:
    assert meta_name(None) == ""


def test_meta_name_handles_unset_name() -> None:
    assert meta_name(V1ObjectMeta()) == ""
