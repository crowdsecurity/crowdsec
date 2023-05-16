/*
Package haversine implements the haversine formula.

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
*/
package haversine
