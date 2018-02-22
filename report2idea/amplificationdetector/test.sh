#!/bin/bash

# input data:
in='
H4sIAPD8jFcAA2NiAIMjmQWJKSlFCi7BIfGeATpQXnCQM4hXmplXYmaiEOQaGO8UGeIaDBcIDoAK
lGTmpiqEePq6xrt5BgWHIPF9HIFckHpjIwXXMFc/oPEuMD7IQDcf//BgZIEAR2dv1xCEENAOVDVA
AWQ1hmZgZwb4B4UwMDCfZghjgALt52zV/4EAxj9cGPQNxO/zYATzl9hbg+lj3uacG+/phunfVTlm
/Ug3DCTLxwrBS5kZGN5xMTCYMiDMrdyh9xebufe5oeautQTT/r3T3+0Bmnvz3PdgR6C5TEAxeRYI
7gGauwTN3PXaxf+xuteHCcw3NK8G03lCzQe2Ac09cGrhUmegucwg93JC8BR2BobdYqjmrv0nI4hs
7uSnjMEg/lNdiLl9vwtg4fByH9BcoPFZLkBzgc5kuM0BwUpAc9NEUc213WQgjM29M6Ug4aA9ywFM
R1huydgPNPf3yo+TQOYCg5UhkgWCfwId/5ob1dyi61W3sJkbcw9ibix3Ipie+3652iGguVEp1vLu
QHPZgGIx7BD8A2jJc0H84XC4cMIhEL/KAhIOrsmlYNox4ekGkLm2XNcPg8wFGsfAxgnBwUDOT1FC
4SuwCsS30YCYez+9CEyvkYlSOQw0l2ONjJUX0FxgsDIc4YBgS6C5q9HMrdT42I8tHGZoQcLB/Rgk
/U6WYCkDhW/cLs8cb6C5QGcyzGCB4LXA8GVHC9+aFy1x2MzdGAvh9/0SBdNva+xNtwDNFVnnfhCU
L4DJlaGQEYKjgJiPBdXcRZ/rw7CZq68AcW9wkh0kPPx7zQ8CzXXuzmH3A5oLdB5DPgsEXwe6twni
XkYGAJhUtVSbBAAA
'

# output data:
out='
H4sIAJWHaVcAA9WZXWvcOBSG7/srgq+3QufoO3dtpoXcpIEJLGwpxTvxlqGTcZhxuoSQ/75HlubL
UscxDIyXNFBs2efoPU+OXskvxVXZVD/q1XNxefG1+PCrnC/Kv+eLefPMJpN6Wnz746K4qe8rf/ul
mP7ZDrupHqqyoDvlw+Ni/s98Vjbzevn9vmqqmf9feKp88E8djile/a1Pv6plczcP95GDeg/8Peo7
bi+5on9/+XfflasfVRPiXi9vy9nPqrmqn5b+Ehpnacjtqm7qNqOn+0f/zP1y3ca+Xn5e1P9uRjsh
/LVb2Q6VgqEAphmgiIM/PjfVZrCwFh3oNs9p/bSaVZsU9l8J6OSxBL48NWkGdDETKcnASgDeXj2c
dIy5mQc4xQAEs8hQ6jbq3fNjm23xkR5ck+JNtdqkkwrYTjGr6/Y9fg5+WtOGqrduqIgL/z7/U0yq
9Ww1f2yrSmWc3EwvDktNYz7Xq4fSv7i4nnz6wP2lq6pcV/naI78EaGuflylR9PXdywj5Bf0GfvEo
Ph1+ud2vOwIDK5nUDFWWYGM557KPYK7UEILbHLoEh0hJBtoqo3IEh5gnIhhlluBW2TMSbFKCtzIl
io6UYN5LsLLg3k4wOMn3C28UozYMoAhhlUHYcqO4Mj0IUxs/ugp0EI5JdBiOoZIUQHFtcm04Rj0J
xF7FDMRR3DNC7BKIdzqlmo6UYttPsTQDfARY1AcUk5NQkqFlYDIQG8mlFLwPYtRmCMQhhw7EMVQK
sUSLkIM4RN1ORRqG6BgwK4YiTBLmEA7Kng9h5AnCO5VSRUeKsOtFWHAFAxDmsF93TVbCWCaJYJch
WKIQxkCfk6D2N4TgkEKH4Bgq/SNCIbNWIgQ9SRf2EmYQjsqOCuGdTKmk40QYsRdhqexRgDq4KTxY
f4E6MBkJQCo92AzFWijneC/F1g7Z0cUsOhTHUGkfRqIyu6cLUU+CsZcxg3FU94wYiwTjnU6ppv9b
jJXGozuqLm/mYC/UZya0E4Cq3xHzQWaizaFrJkKojJlQSvzGEfMMxCAlLStyqJ/QcZZZcUdF8U6o
VNSRUiz6KSbnNoRi6QZZYkei9VKMclArDjkklrgNlaEYhMGsJZYHrXhjiTVNhQ+FmETMQRy0PSPE
OmOKNzqlmo4T4jeYYtr1DHAUTsJ+4RGY5LT+kjeW2fM1R5jHpfaYKzZ6AMQhh+75WoiUWQykzLqJ
EPM052skYe58LSh7RoQz52tbmRJFx0kw7z+ZAC4GnEwIeVB3pA4skAH9xvW32wMlF/EDwO8JFvro
CV8H4JBCB+AYKEkA6WJuVxdCnoRfL2CG36jrqL5w7FRKBB0nvwj9HdjJo+2v04HtwWZe+4KTgUTD
rM6dS3DaNvH+DiwGfeGwmW90MVLagWkXnj+WEKf7wkES5jpwUPZ8BIvMscRWpkTR13f/ATa2UDZk
HgAA
'

test -z "$srcdir" && export srcdir=.

. $srcdir/../test.sh

test_conversion "amplification" "amplification" "$in" "$out"

