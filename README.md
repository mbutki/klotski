This project directory contains the Klotski webproxy. launch_proxy.sh can be used to run it. current_url.txt is read by the proxy whenever a request comes in to let the proxy know what website info to use from the fingerprint file. It should be updated by an outside program before each website load. fingerprint.json is an example of a fingerprint file, which tells Klotski what to push and what to reprioritize. Some of the important fields in the fingerprint file are:

- pattern2match_set: a dynamic url pattern, and all the resources it matched
- static_set: a set of all known static resource urls
- resource2vals:
-- select_type: this tells Klotski if it should push it or just reprioritize it.
-- response_headers: This has compression information which is needed when pushing the resource in the future.
-- priority: This is the spdy priority we will use for the resource.
- resources:
-- select_type: either push or reprioritize the SPDY priority
-- encoding: used for pushing

The code is extremely hacky. There are many odd things. If you can't get it working correctly I would recommend getting a fresh copy of node-spdyproxy and using the Klotski modifications as a rough guide to how to modify it for your needs. Klotski and node-spdyproxy have diverged so much that I don't think there's an easy way to upgrade Klotski with the updated node-spdyproxy code. 
