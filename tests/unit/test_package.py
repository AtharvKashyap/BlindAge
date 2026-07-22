import blindage


def test_package_importable_with_version():
    assert blindage.__version__ == "0.1.0"
