;;; -*- Syntax: Ansi-common-lisp; Package: cl-USER; Base: 10; Mode: LISP -*- 

(in-package :cl-user)

(defvar *aplan-home-directory* :not-yet)
(defvar *aplan-wild-directory* :not-yet)

(eval-when (:execute :load-toplevel)
  (let* ((loading-file *load-truename*)
	 (host (pathname-host loading-file))
	 (device (pathname-device loading-file))
	 (home-dir (pathname-directory loading-file))
	 (wild-dir (append home-dir (list :wild-inferiors))))
    (setq *aplan-home-directory* (make-pathname :directory home-dir 
						 :host host 
						 :device device)
	  *aplan-wild-directory* (make-pathname :directory wild-dir
						 :host host 
						 :device device
						 :type :wild
						 :name :wild
						 :version :unspecific))
    (setf (logical-pathname-translations "aplan")
      `(("home;*.*"	,*aplan-home-directory*)
	("**;*.*"	,*aplan-wild-directory*)
	))
    (pushnew (namestring (truename #P"aplan:home;my-logical-pathnames.lisp"))
	       (logical-pathname-translations-database-pathnames)
	       :test #'string-equal)      
      (with-open-file (F #P"aplan:home;my-logical-pathnames.lisp" :direction :output :if-exists :supersede)
	(format f "~%;;; aplan")
	(format f "~2%~s" "aplan")
	(loop for (a b) in (logical-pathname-translations "aplan")
	  do (format f "~%'(~s ~s)" (namestring a) (namestring b)))
	(terpri f)
	))
  )


#+allegro
(defsystem aplan 
    (:default-pathname "aplan:home;"
	:default-module-class separate-destination-module)
  (:serial
   ("package-definition")
   ("predicate-defs" (:module-class separate-destination-joshua-module))
   ("object-defs" (:module-class separate-destination-joshua-module))
   ("macros" (:module-class separate-destination-joshua-module))
   ("threading-objects" (:module-class separate-destination-joshua-module))
   ("ip-locations-and-masks" (:module-class separate-destination-joshua-module))
   ("def-attack-method" (:module-class separate-destination-joshua-module))
   ("system-dependencies" (:module-class separate-destination-joshua-module))
   ("ai-lab-description" (:module-class data-module))
   ("jbi-example" (:module-class data-module))   
   ("editor" (:module-class separate-destination-joshua-module))
   ("attack-graphics" (:module-class separate-destination-joshua-module))
   ))

