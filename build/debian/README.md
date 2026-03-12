
# Building Debian/Ubuntu packages

It is not recommended to build your own packages for production environments.

However, if you want to experiment and contribute:

* Update the changelog (at least give it a correct version number)
* Run "QUILT_PATCHES=debian/patches quilt push -a && quilt refresh"

We do the above in the build pipeline, so you'll have to do it manually before running:

* dpkg-buildpackage -uc -us -b

