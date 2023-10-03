Basic API usage
===============

Loading identities from a uSWID-format container:

.. code-block:: python

    from uswid import uSwidFormatUswid

    with open(filename, "rb") as f:
        for identity in uSwidFormatUswid().load(f.read()):
            print(f"{identity!s}")

Loading identities from a possible PE file:

.. code-block:: python

    import pefile
    from uswid import uSwidFormatCoswid

    try:
        with open(filename, "rb") as f:
            pe = pefile.PE(data=f.read())
        for sect in pe.sections:
            if sect.Name == b".sbom\0\0\0":
                for identity in uSwidFormatCoswid().load(sect.get_data()):
                    print(f"{identity!s}")
    except pefile.PEFormatError:
        # not a PE file, which is fine
        pass

Creating a new identity, entity and payload:

.. code-block:: python

    from uswid import (
        uSwidIdentity,
        uSwidEntity,
        uSwidEntityRole,
        uSwidPayload,
        uSwidHash,
    )

    identity = uSwidIdentity(
        tag_id="foo",
        software_name="bar",
        software_version="baz",
    )
    identity.add_entity(
        uSwidEntity(
            name="me",
            regid="example.domain",
            roles=[uSwidEntityRole.TAG_CREATOR, uSwidEntityRole.DISTRIBUTOR],
        )
    )
    payload = uSwidPayload(name="foo.bin", size=123)
    payload.add_hash(
        uSwidHash(
            alg_id=uSwidHashAlg.SHA256,
            value="067cb8292dc062eabbe05734ef7987eb1333b6b6",
        )
    )
    identity.add_payload(payload)

Saving all three to an XML SWID file:

.. code-block:: python

    from uswid import uSwidContainer, uSwidFormatSwid

    with open(filename, "rw") as f:
        f.write(uSwidFormatSwid().save(uSwidContainer([identity])))

