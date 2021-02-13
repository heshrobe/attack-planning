;;; -*- Syntax: Ansi-common-lisp; Package: cl-USER; Base: 10; Mode: LISP -*- 

(in-package :cl-user)

;;; If we're using swank (i.e. slime) then associate
;;; the joshua readtable with the APLAN package
;;; so the we read in Joshua syntax
#+swank
(pushnew (cons "APLAN" ji::*joshua-readtable*)
	 swank:*readtable-alist*
	 :key #'first
	 :test #'string=)

(eval-when (:execute :load-toplevel)
  (let* ((loading-file *load-truename*)
         (host (pathname-host loading-file))
         (device (pathname-device loading-file))
         (home-dir (pathname-directory loading-file))
         (wild-dir (append (butlast home-dir) (list :wild-inferiors))))
    (let ((aplan-home-directory (make-pathname :directory home-dir 
					       :host host 
					       :device device))
	  #+sbcl (aplan-newest-directory (make-pathname :directory wild-dir
							:host host 
							:device device
							:type :wild
							:name :wild
							:version :newest))
          (aplan-wild-directory (make-pathname :directory wild-dir
					       :host host 
					       :device device
					       :type :wild
					       :name :wild
					       :version :unspecific)))
      (setf (logical-pathname-translations "aplan")
	    `(("home;*.*"	,aplan-home-directory)
	      ;; sbcl's version of open insists on putting newest into
	      ;; a logical pathname and this causes an error
	      ;; the line below fixes that
	      #+sbcl ("**;*.*.newest" ,aplan-newest-directory)
	      ("**;*.*"	,aplan-wild-directory)
	      )))
    #+allegro
    (with-open-file (F #P"aplan:home;my-logical-pathnames.lisp" :direction :output :if-exists :supersede :if-does-not-exist :create)
      (format f "~%;;; aplan")
      (format f "~2%~s" "aplan")
      (loop for (a b) in (logical-pathname-translations "aplan")
          do (format f "~%'(~s ~s)" (namestring a) (namestring b)))
      (terpri f)
      )
    #+allegro
    (pushnew (namestring (truename #P"aplan:home;my-logical-pathnames.lisp"))
             (logical-pathname-translations-database-pathnames)
             :test #'string-equal))
  )

;;; The joshua asd file includes this
;; (load "~/josh-dist/joshua/code/asdf-support.lisp")

(asdf:defsystem aplan/core
  :name "aplan-core"
  :description "Attack Plan Generator Core Functionality No UI"
  :maintainer "Howie Shrobe"
  :pathname "."
  :components ((:file "package-definition")
	       (:joshua-file "predicate-defs" :depends-on ("package-definition"))
	       (:joshua-file "stateful-predicates" :depends-on ("predicate-defs"))
	       (:joshua-file "object-defs" :depends-on ("stateful-predicates"))
	       (:joshua-file "macros" :depends-on ("object-defs"))
               (:joshua-file "background-knowledge" :depends-on ("macros"))
	       (:joshua-file "def-attack-method" :depends-on ("macros"))
	       (:joshua-file "predicate-methods" :depends-on ("def-attack-method"))
	       (:joshua-file "goals" :depends-on ("predicate-methods"))
	       (:joshua-file "actions" :depends-on ("goals"))
	       (:joshua-file "threading-objects" :depends-on ("actions"))
	       (:joshua-file "ip-locations-and-masks" :depends-on ("threading-objects"))
	       (:joshua-file "attack-methods" :depends-on ("ip-locations-and-masks"))
	       (:joshua-file "core-reasoning" :depends-on ("attack-methods"))
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
		 (:joshua-file "attack-graphics" :depends-on ("editor"))
                 (:Joshua-file "plan-recognizer" :depends-on ("attack-graphics"))
                 ))

(asdf:defsystem aplan
    :name "aplan"
    :description "Full Attack Plan Generator"
    :maintainer "Howie Shrobe"
    :pathname "."
    :depends-on ("aplan/core" "aplan/ui")
    )
  

