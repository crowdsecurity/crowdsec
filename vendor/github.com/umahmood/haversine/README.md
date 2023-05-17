[![Build Status](https://travis-ci.org/umahmood/haversine.svg?branch=master)](https://travis-ci.org/umahmood/haversine)

# Haversine

Package haversine is a Go library which implements the haversine formula. The 
haversine formula gives great-circle distances between two points on a sphere 
from their longitudes and latitudes. The sphere in this case is the surface of 
the Earth.

![Earth great circle](https://i.imgur.com/iD3X3Ax.png)

*The dotted yellow line is an arc of a great circle. It gives the shortest 
distance between the two yellow points. Image courtesy USGS.*

# Installation

> go get github.com/umahmood/haversine

> cd $GOPATH/src/github.com/umahmood/haversine/

> go test -v ./...

# Usage

The below example shows how to calculate the shortest path between two 
coordinates on the surface of the Earth.

    package main

    import (
        "fmt"

        "github.com/umahmood/haversine"
    )

    func main() {
        oxford := haversine.Coord{Lat: 51.45, Lon: 1.15}  // Oxford, UK
        turin  := haversine.Coord{Lat: 45.04, Lon: 7.42}  // Turin, Italy
        mi, km := haversine.Distance(oxford, turin)
        fmt.Println("Miles:", mi, "Kilometers:", km)
    }

# Documenation

> http://godoc.org/github.com/umahmood/haversine

# References

* https://plus.maths.org/content/lost-lovely-haversine
* https://en.wikipedia.org/wiki/Haversine_formula

# License

See the [LICENSE](LICENSE.md) file for license rights and limitations (MIT).
