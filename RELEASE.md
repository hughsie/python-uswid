# Release Process

    export release_ver="0.4.4"
    git commit -a -m "Release ${release_ver}"
    git tag -s -f -m "Release ${release_ver}" "${release_ver}"
    make pkg
    ./env/bin/twine upload dist/uswid-${release_ver}*
    # edit setup.py
    git commit -a -m "trivial: post release version bump"
    git push
    git push --tags
