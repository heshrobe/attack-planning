{
"nodes":[

{"id":"goal1"
,"type":"goal"
,"goal":"affect"
,"attacker":"typicalAttacker"
,"property":"accuracy"
,"thing":"autoPilotProcess"
,"machine":"controllerboard"}
,
{"id":"or66"
,"type":"or"}
,
{"id":"plan63"
,"type":"plan"
,"combinator":"singleton"}
,
{"id":"goal45"
,"type":"goal"
,"goal":"affect"
,"attacker":"typicalAttacker"
,"property":"dataIntegrity"
,"thing":"waypointSequence"}
,
{"id":"plan62"
,"type":"plan"
,"combinator":"sequential"}
,
{"id":"goal46"
,"type":"goal"
,"goal":"takesControlOf"
,"attacker":"typicalAttacker"
,"componentProperty":"dataIntegrity"
,"component":"navigationProcess"}
,
{"id":"plan58"
,"type":"plan"
,"combinator":"singleton"}
,
{"id":"goal47"
,"type":"goal"
,"goal":"takesIndirectControlOf"
,"attacker":"typicalAttacker"
,"componentProperty":"dataIntegrity"
,"component":"navigationProcess"}
,
{"id":"plan57"
,"type":"plan"
,"combinator":"singleton"}
,
{"id":"goal48"
,"type":"goal"
,"goal":"modify"
,"attacker":"typicalAttacker"
,"objectProperty":"contents"
,"object":"waypointSequence"}
,
{"id":"plan56"
,"type":"plan"
,"combinator":"sequential"}
,
{"id":"goal49"
,"type":"goal"
,"goal":"achieveAccessRight"
,"attacker":"typicalAttacker"
,"operation":"write"
,"thing":"waypointSequence"
,"principal":"controllerAdministrator"}
,
{"id":"or65"
,"type":"or"}
,
{"id":"plan14"
,"type":"plan"
,"combinator":"singleton"}
,
{"id":"goal3"
,"type":"goal"
,"goal":"remoteShell"
,"attacker":"typicalAttacker"
,"user":"controllerAdministrator"
,"osInstance":"os"}
,
{"id":"plan13"
,"type":"plan"
,"combinator":"sequential"}
,
{"id":"goal4"
,"type":"goal"
,"goal":"achieveKnowledgeOfPassword"
,"attacker":"typicalAttacker"
,"victim":"controllerAdministrator"
,"entity":"controllerPool"}
,
{"id":"plan8"
,"type":"plan"
,"combinator":"singleton"}
,
{"id":"goal5"
,"type":"goal"
,"goal":"guessPassword"
,"attacker":"typicalAttacker"
,"user":"controllerAdministrator"
,"resource":"controllerPool"}
,
{"id":"plan7"
,"type":"plan"
,"combinator":"singleton"}
,
{"id":"action6"
,"type":"action"
,"action":"passwordDictionaryLookupAttack"
,"actor":"typicalAttacker"
,"user":"controllerAdministrator"}
,
{"id":"goal9"
,"type":"goal"
,"goal":"achieveConnection"
,"attacker":"typicalAttacker"
,"osInstance":"os"
,"connectionType":"ssh"}
,
{"id":"plan11"
,"type":"plan"
,"combinator":"singleton"}
,
{"id":"action10"
,"type":"action"
,"action":"connectVia"
,"actor":"typicalAttacker"
,"machine":"controllerboard"
,"protocolName":"ssh"}
,
{"id":"action12"
,"type":"action"
,"action":"login"
,"actor":"typicalAttacker"
,"user":"controllerAdministrator"
,"osInstance":"os"}
,
{"id":"plan54"
,"type":"plan"
,"combinator":"sequential"}
,
{"id":"goal50"
,"type":"goal"
,"goal":"takesDirectControlOf"
,"attacker":"typicalAttacker"
,"componentProperty":"execution"
,"component":"controllerboardwebserver"}
,
{"id":"plan52"
,"type":"plan"
,"combinator":"singleton"}
,
{"id":"action51"
,"type":"action"
,"action":"takeControlWithBufferOverflow"
,"actor":"typicalAttacker"
,"process":"controllerboardwebserver"}
,
{"id":"action53"
,"type":"action"
,"action":"usesControlToAchieveAccessRight"
,"attacker":"typicalAttacker"
,"right":"write"
,"component":"waypointSequence"}
,
{"id":"action55"
,"type":"action"
,"action":"useAccessRightToModify"}
,
{"id":"goal59"
,"type":"goal"
,"goal":"useControlOfToAffectResource"
,"attacker":"typicalAttacker"
,"controlledThing":"navigationProcess"
,"property":"dataIntegrity"
,"resource":"waypointSequence"}
,
{"id":"plan61"
,"type":"plan"
,"combinator":"singleton"}
,
{"id":"action60"
,"type":"action"
,"action":"modifyInCoreDataStructures"
,"actor":"navigationProcess"
,"dataStructure":"waypointSequence"}
,
{"id":"plan44"
,"type":"plan"
,"combinator":"singleton"}
,
{"id":"goal41"
,"type":"goal"
,"goal":"affect"
,"attacker":"typicalAttacker"
,"property":"dataIntegrity"
,"thing":"insPosition"}
,
{"id":"plan43"
,"type":"plan"
,"combinator":"singleton"}
,
{"id":"action42"
,"type":"action"
,"action":"signalNoiseInjection"
,"attacker":"typicalAttacker"
,"sensor":"ins"
,"signal":"insPosition"}
,
{"id":"plan40"
,"type":"plan"
,"combinator":"singleton"}
,
{"id":"goal37"
,"type":"goal"
,"goal":"affect"
,"attacker":"typicalAttacker"
,"property":"dataIntegrity"
,"thing":"vorPosition"}
,
{"id":"plan39"
,"type":"plan"
,"combinator":"singleton"}
,
{"id":"action38"
,"type":"action"
,"action":"signalNoiseInjection"
,"attacker":"typicalAttacker"
,"sensor":"vor"
,"signal":"vorPosition"}
,
{"id":"plan36"
,"type":"plan"
,"combinator":"singleton"}
,
{"id":"goal33"
,"type":"goal"
,"goal":"affect"
,"attacker":"typicalAttacker"
,"property":"dataIntegrity"
,"thing":"gpsPosition"}
,
{"id":"plan35"
,"type":"plan"
,"combinator":"singleton"}
,
{"id":"action34"
,"type":"action"
,"action":"signalNoiseInjection"
,"attacker":"typicalAttacker"
,"sensor":"gps"
,"signal":"gpsPosition"}
,
{"id":"plan32"
,"type":"plan"
,"combinator":"sequential"}
,
{"id":"goal17"
,"type":"goal"
,"goal":"remoteExecution"
,"attacker":"typicalAttacker"
,"entity":"controllerboardwebserver"
,"osInstance":"os"}
,
{"id":"or64"
,"type":"or"}
,
{"id":"plan26"
,"type":"plan"
,"combinator":"singleton"}
,
{"id":"goal23"
,"type":"goal"
,"goal":"codeReuse"
,"attacker":"typicalAttacker"
,"process":"controllerboardwebserver"
,"osInstance":"os"}
,
{"id":"plan25"
,"type":"plan"
,"combinator":"singleton"}
,
{"id":"action24"
,"type":"action"
,"action":"launchCodeReuseAttack"
,"attacker":"typicalAttacker"
,"process":"controllerboardwebserver"}
,
{"id":"plan21"
,"type":"plan"
,"combinator":"singleton"}
,
{"id":"goal18"
,"type":"goal"
,"goal":"codeInjection"
,"attacker":"typicalAttacker"
,"process":"controllerboardwebserver"
,"osInstance":"os"}
,
{"id":"plan20"
,"type":"plan"
,"combinator":"singleton"}
,
{"id":"action19"
,"type":"action"
,"action":"launchCodeInjectionAttack"
,"attacker":"typicalAttacker"
,"process":"controllerboardwebserver"}
,
{"id":"action30"
,"type":"action"
,"action":"issueFalseSensorDataReport"}
,
{"id":"plan31"
,"type":"plan"
,"combinator":"sequential"}
,
{"id":"goal2"
,"type":"goal"
,"goal":"remoteExecution"
,"attacker":"typicalAttacker"
,"entity":"controllerAdministrator"
,"osInstance":"os"}
,
{"id":"plan29"
,"type":"plan"
,"combinator":"sequential"}
,
{"id":"action27"
,"type":"action"
,"action":"issueFalseSensorDataReport"}
,
{"id":"plan28"
,"type":"plan"
,"combinator":"sequential"}
,
{"id":"plan22"
,"type":"plan"
,"combinator":"sequential"}
,
{"id":"action15"
,"type":"action"
,"action":"issueFalseSensorDataReport"}
,
{"id":"plan16"
,"type":"plan"
,"combinator":"sequential"}]
,"links":[

{"id":"goal1","destinations":["or66"]}

{"id":"or66","destinations":["plan63","plan44","plan40","plan36","plan32","plan31","plan29","plan28","plan22","plan16"]}

{"id":"plan63","destinations":["goal45"]}

{"id":"goal45","destinations":["plan62"]}

{"id":"plan62","destinations":["goal46","goal59"]}

{"id":"goal46","destinations":["plan58"]}

{"id":"plan58","destinations":["goal47"]}

{"id":"goal47","destinations":["plan57"]}

{"id":"plan57","destinations":["goal48"]}

{"id":"goal48","destinations":["plan56"]}

{"id":"plan56","destinations":["goal49","action55"]}

{"id":"goal49","destinations":["or65"]}

{"id":"or65","destinations":["plan14","plan54"]}

{"id":"plan14","destinations":["goal3"]}

{"id":"goal3","destinations":["plan13"]}

{"id":"plan13","destinations":["goal4","goal9","action12"]}

{"id":"goal4","destinations":["plan8"]}

{"id":"plan8","destinations":["goal5"]}

{"id":"goal5","destinations":["plan7"]}

{"id":"plan7","destinations":["action6"]}


{"id":"goal9","destinations":["plan11"]}

{"id":"plan11","destinations":["action10"]}



{"id":"plan54","destinations":["goal50","action53"]}

{"id":"goal50","destinations":["plan52"]}

{"id":"plan52","destinations":["action51"]}




{"id":"goal59","destinations":["plan61"]}

{"id":"plan61","destinations":["action60"]}


{"id":"plan44","destinations":["goal41"]}

{"id":"goal41","destinations":["plan43"]}

{"id":"plan43","destinations":["action42"]}


{"id":"plan40","destinations":["goal37"]}

{"id":"goal37","destinations":["plan39"]}

{"id":"plan39","destinations":["action38"]}


{"id":"plan36","destinations":["goal33"]}

{"id":"goal33","destinations":["plan35"]}

{"id":"plan35","destinations":["action34"]}


{"id":"plan32","destinations":["goal17","action30"]}

{"id":"goal17","destinations":["or64"]}

{"id":"or64","destinations":["plan26","plan21"]}

{"id":"plan26","destinations":["goal23"]}

{"id":"goal23","destinations":["plan25"]}

{"id":"plan25","destinations":["action24"]}


{"id":"plan21","destinations":["goal18"]}

{"id":"goal18","destinations":["plan20"]}

{"id":"plan20","destinations":["action19"]}



{"id":"plan31","destinations":["goal2","action30"]}

{"id":"goal2","destinations":["plan14"]}

{"id":"plan29","destinations":["goal17","action27"]}


{"id":"plan28","destinations":["goal2","action27"]}

{"id":"plan22","destinations":["goal17","action15"]}


{"id":"plan16","destinations":["goal2","action15"]}]}