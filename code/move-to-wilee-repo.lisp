;;; -*- Mode: Common-lisp; Package: aplan -*=

(in-package :aplan)

(defparameter *big-files* (list ))

(defparameter *repo-aplan-pathname* #p"~/Research-Projects/CHASE/threat-planner/threat_planner/aplan/")
(defparameter *repo-joshua-pathname* #p"~/Research-Projects/CHASE/threat-planner/threat_planner/joshua/")
(defparameter *repo-models-pathname* #p"~/Research-Projects/CHASE/threat-planner/threat_planner/aplan/mirai-for-wilee-example.lisp")


(defparameter *local-aplan-pathname* #p"~/Research-Projects/attack-planning/code/*.lisp")
(defparameter *local-joshua-pathname* #p"~/josh-dist/joshua/code/*.lisp")
(defparameter *local-models-pathname* #p"~/Research-Projects/attack-planning/models/mirai-for-wilee-example.lisp")


(defparameter *excluded-files* (list #p"~/Research-Projects/attack-planning/code/move-to-wilee-repo.lisp"
				     #p"~/Research-Projects/attack-planning/code/defsystem"
				     #p"~/Research-Projects/attack-planning/code/attack-graphics.lisp"
				     #p"~/Research-Projects/attack-planning/code/editor.lisp"
				     #p"~/Research-Projects/attack-planning/code/emacs-hacks.lisp"
				     #p"~/Research-Projects/attack-planning/code/my-logical-pathnamess.lisp"
				     #p"~/josh-dist/joshua/code/original-mapforms.lisp"
				     #p"~/josh-dist/joshua/code/cloehacks.lisp"
				     #p"~/josh-dist/joshua/code/joshua-defsystem.lisp"
				     #p"~/josh-dist/joshua/code/move-to-wilee-repo.lisp"
				     ))

(defun move-to-wilee-repo (&optional (force nil))
  (labels ((skip-this-pathname (pathname)
	     (member (namestring pathname) *excluded-files* :test #'string-equal :key #'namestring))
	   (do-a-pair (source-pathname destination-pathname)
	     (let ((all-files (append (cl:directory (merge-pathnames "*.lisp" source-pathname) )
				      (cl:directory (merge-pathnames "*.asd" source-pathname)))))
	       (loop for file in all-files
		   unless (or (skip-this-pathname file) 
			      (find #\# (pathname-name file) :test #'char-equal))
		   do (let ((destination (make-pathname :name (pathname-name file)
							:type (pathname-type file) 
							:directory (pathname-directory destination-pathname))))
			(if (or force
				(null (probe-file destination))
				(null (file-write-date destination))
				(> (file-write-date file) (file-write-date destination)))
			    (sys:copy-file file destination :overwrite t :verbose t)
			  (format t "~%File ~a is up to date" file)))))))
    (do-a-pair *local-aplan-pathname* *repo-aplan-pathname*)
    (do-a-pair *local-joshua-pathname* *repo-joshua-pathname*)
    (sys:copy-file *local-models-pathname* *repo-models-pathname* :overwrite t :verbose t)
	     ))
 
