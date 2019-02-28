;;; -*- Syntax: Ansi-common-lisp; Package: cl-USER; Base: 10; Mode: LISP -*- 

(in-package :cl-user)

(asdf:defsystem aplan/core
  :name "aplan-core"
  :description "Attack Plan Generator Core Functionality No UI"
  :maintainer "Howie Shrobe"
  :pathname "."
  :components ((:file "package-definition")
	       (:joshua-file "predicate-defs" :depends-on ("package-definition"))
	       (:joshua-file "object-defs" :depends-on ("predicate-defs"))
	       (:joshua-file "macros" :depends-on ("object-defs"))
	       (:joshua-file "threading-objects" :depends-on ("macros"))
	       (:joshua-file "ip-locations-and-masks" :depends-on ("threading-objects"))
	       (:joshua-file "def-attack-method" :depends-on ("ip-locations-and-masks"))
	       (:joshua-file "system-dependencies" :depends-on ("def-attack-method"))
	       (:joshua-file "core-reasoning" :depends-on ("system-dependencies"))
	       (:joshua-file "json-dumper" :depends-on ("core-reasoning"))
	       ))

(asdf:defsystem aplan/ui
    :name "aplan-ui"
    :description "Attack Plan Generator UI Components"
    :maintainer "Howie Shrobe"
    :pathname "."
    :depends-on ("aplan/core")
    :components (
		 (:joshua-file "editor")
		 (:joshua-file "attack-graphics" :depends-on ("editor")))
    )

(asdf:defsystem aplan
    :name "aplan"
    :description "Full Attack Plan Generator"
    :maintainer "Howie Shrobe"
    :pathname "."
    :depends-on ("aplan/core" "aplan/ui")
    )
  

