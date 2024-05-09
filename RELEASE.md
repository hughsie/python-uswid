# Release Process

1. Write NEWS entries in the same format as usual.

    git shortlog 0.5.0.. | grep -i -v trivial | grep -v Merge > NEWS.new
    # add entries to ./docs/source/versionhistory.rst

Commit changes to git:

    # MAKE SURE THAT setup.py IS ALSO CORRECT
    export release_ver="0.5.1"
    git commit -a -m "Release ${release_ver}"
    git tag -s -f -m "Release ${release_ver}" "${release_ver}"
    make pkg
    ./env/bin/twine upload dist/uswid-${release_ver}*

Do post release version bump in setup.py:

    git commit -a -m "trivial: post release version bump"
    git push
    git push --tags
