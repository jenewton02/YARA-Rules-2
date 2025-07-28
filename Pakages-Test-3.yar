// rule file (save as "md5_match.yara")

import "hash" 

rule Pakages-Test-1 {

    meta:
        description = "Ubuntu 22.04 Download"

    strings:
        $m0 = { 4D 5A } // wide ascii

    condition:
        $m0 at 0   and 
        filesize < 1GB and
        hash.md5(0, filesize) == "1c672b170ef5e1a89a6f8a792fdc48d3"     
}