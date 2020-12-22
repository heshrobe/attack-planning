;;; -*- Syntax: Joshua; Package: APLAN; readtable: Joshua; Mode: Common-lisp  -*-

(in-package :aplan) 

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Restorable predicates
;;;
;;; There are some facts about the world that we want to preserve even after
;;; we've cleared the joshua database to remove a specific "environment model" 
;;; 
;;; We'll have a list of predicates to retell and appropriate
;;; predicate-methods to make this work
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defparameter *predicates-to-retell* nil)

(define-predicate-model restorable-predicate () (ltms:ltms-predicate-model))

(define-predicate-method (tell restorable-predicate :after) (truth-value justification)
  ;; I'm assuming that all of these are premises
  (declare (ignore justification))
  (pushnew (list (predication-statement self) truth-value) *predicates-to-retell* :test #'equal))

(define-predicate-method (after-clear restorable-predicate :after) (&optional clear-database undefrules)
  (when (and clear-database (not undefrules))
    (loop for (statement truth-value) in *predicates-to-retell*
	if (eql truth-value +true+)
	do (let ((pred (make-predication statement)))
	     (ji:tell-internal pred +true+ :premise)
	     )
	else do
	   (let* ((inner-pred (make-predication statement))
		  (outer-pred `[not ,inner-pred]))
	     (tell outer-pred :justification :premise)))))



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Macro for defining our predicates
;;;  Fill in ltms:ltms-predicate-model
;;;  collect predicate name in a global variable
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(eval-when (:load-toplevel :compile-toplevel :execute)
  (defparameter *all-aplan-predicates* nil)
  
  (define-predicate-model aplan-predicate-model () (ltms:ltms-predicate-model))

  (defmacro define-aplan-predicate (name parameters models)
    (let ((all-models (if (member 'aplan-predicate-model models) 
                          models
                        (append models (list 'aplan-predicate-model)))))
      `(eval-when (:load-toplevel :compile-toplevel :execute)
         (pushnew ',name *all-aplan-predicates*)
         (define-predicate ,name ,parameters ,all-models)))))



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Non Stateful Predicates
;;;  Most predicates in the planner are termporally contigent
;;;  That is they are true only at certain points in time
;;;
;;;  But there are a lot of predicates that are Background Knowledge
;;;   and are not temporally contigent, they are always true and are
;;;   asserted in the starting environment of the planner
;;;   these are the non-stateful predicates
;;;
;;; These are compiled differenlty by def-attack-method and define-action in
;;; that they aren't embedded inside an in-state predication
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-predicate-model non-stateful-predicate-model () (ltms:ltms-predicate-model))



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Predicates that are carried along within the structure of the planner in a special way.
;;;
;;; Part of the state of the attacker is where he/she/they currently have a foothold and in what role
;;;  Instead of passing this along as arguments to each method, it's treated as hidden state that
;;;  can be updated and retrieved with the predicates below.
;;;
;;; By keepin track of what footholds the attacker has already achieved 
;;;  the planner can avoid trying to get the same foothold twice
;;;
;;; Footholds are machines that are capable of reaching a target machine using a specific protocol
;;;  I.e. if you want to attack Foo you can try to get a foothold on Bar if Bar can talk to Foo 
;;;       using a specific protocol.
;;;  So getting a foothold to Foo may involve getting remote execution on Bar
;;; But Bar may not be accessible from whereever the attacker currently has a foothold,
;;;  So get-remote-execution will try to get a foothold for Bar.
;;;
;;; In order to manage all this we need to keep track of what footholds the attacker
;;;  currently has (these are facts about the world)
;;;
;;; In addition we need to keep track of the state of the planner itself
;;;  In particular, what machines has it already considered in the sub-goaling
;;;  described above.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; A predicate that is handled in a special way by the in-state machinery
;;; Typically it has an Ask-data method and doesn't have an actual interned predication
(define-predicate-model special-stateful-predicate-model () (ltms:ltms-predicate-model))

;;; Current-foothold always occurs within the :bindings clause which wraps it inside an [in-state ... ]
;;; It's only asked

(define-aplan-predicate current-foothold (foothold-machine foothold-role) (special-stateful-predicate-model))

;;; Foothold-exists always occurs within the :guards clause which wraps it inside an [in-state ... ]
;;; so this is always asked
(define-predicate foothold-doesnt-exist (victim-machine) (special-stateful-predicate-model))

;;; Has-Foothold will appear in a post-conditions clause which wraps it in an [in-state .... ]
;;; It can be both asserted and queried.
(define-predicate has-foothold (victim-machine foothold-machine foothold-role protocol-name) (special-stateful-predicate-model))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; The purpose of this next set of predicates is to break cycles in searches initiated by get-foothold or get-remote-execution
;;; These keep track of where we have been in the search (as opposed to some fact about the world)
;;; if it's for a foothold we'll also remember the protocol that that foothold needs to be able
;;; to use to talk to the target
;;; This one is always used inside a [in-state ... ] predication
;;; so the state doesn't need to be in the predication
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-predicate place-already-visited? (machine purpose) (tell-error-model special-stateful-predicate-model))

;;; Place-visited always occurs as a note within the :plan structure and the macro expansion
;;; puts the input and output states into the predication.
(define-predicate place-visited (machine purpose) (special-stateful-predicate-model))



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Predicates for retrieving properties and components of objects
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-predicate named-component (superpart-object name subpart-object) 
  (ji::named-part-of-mixin ltms:ltms-predicate-model))

(define-predicate component (superpart-object subpart-object) (ji::part-of-mixin ltms:ltms-predicate-model))

(define-predicate value-of (path variable) (ji::slot-value-mixin ltms:ltms-mixin default-protocol-implementation-model))



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Factual Predicates -- Describing features of the world
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; This just retrieves who the attacker is and what the attacker's home machine is
(define-aplan-predicate attacker-and-machine (attacker attacker-machine) (special-stateful-predicate-model))

;;; There might be more like these, they retrieve systems under the attacker's control for some purpose
;;; It might be better to have a more general predicate that lists the role, rather than several separate
;;; predicates (e.g. there might be a soft-update-server under the attacker's control)
(define-aplan-predicate attacker-download-server (attacker attacker-server-machine) (non-stateful-predicate-model))
(define-aplan-predicate attacker-adware-server (attacker attacker-server-machine) (non-stateful-predicate-model))

(define-aplan-predicate desirable-property-of (system property) (non-stateful-predicate-model))

;;; This is used in the sense that a process controls a data-set
(define-aplan-predicate process-controls-data-set (thing1 thing2) (non-stateful-predicate-model))

;;; Some property of one component affects a property of another component of the OS
(define-aplan-predicate impacts (feature component property thing) (non-stateful-predicate-model))

(define-aplan-predicate input-of (component resource) (non-stateful-predicate-model))

(define-aplan-predicate output-of (component resource) (non-stateful-predicate-model))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; These are used in reasoning about life-cycle attacks
;;;
;;; A residence is a place that a piece of code can live, such as the file system or memory
;;; A format is something like source, object, linkable, binary-in-memory
;;; Migrates-from describes how a process can move software from one residence to another
;;; Transforms describes a process (e.g. compiler, linker, loader) that produces a new format of the software
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-aplan-predicate residence (thing place) (non-stateful-predicate-model))

(define-aplan-predicate migrates-from (thing place1 place2 process) (non-stateful-predicate-model))

(define-aplan-predicate is-a-format-of (thing format-type other-thing) (non-stateful-predicate-model))

(define-aplan-predicate transforms (process format1 format2) (non-stateful-predicate-model))



;;; I'm treating these as if they are not temporally contingent.
;;; However, if we were reasoning about mitigations that attacker might employ
;;; then installing a patch could change these and you could imagine an attacker in which
;;; the attacker gets the user to install a patch that introduces a vulnerabiity (e.g. Solar Winds)
;;; in which case these should be normal stateful predicates.
(define-aplan-predicate is-vulnerable-to (process attack-type protocol) (non-stateful-predicate-model))
(define-aplan-predicate protected-from (thing attack protocol) (non-stateful-predicate-model))
(define-aplan-predicate vulnerable-to-capec (thing capec cve-number) (non-stateful-predicate-model))

;;; I think I got rid of the need for these.
;;; (define-aplan-predicate vulnerable-to (thing attack) (non-stateful-predicate-model))
;;; (define-predicate vulnerable-to-overflow-attack (process protocol) (ltms:ltms-predicate-model))

(define-aplan-predicate is-typical-user (user) (non-stateful-predicate-model))

;;; I'm treating this as if it's not temporally contingent.  There's a
;;; temporally contingent predicate just below runs-with-permission-of
;;; that says someone is running with superuser privilege,

(define-aplan-predicate is-superuser (user machine) (non-stateful-predicate-model))

;;; These could change over time (I think)

(define-aplan-predicate has-permission (user operation object) ())

(define-predicate runs-with-permissions-of (process user) (ltms:ltms-predicate-model))

(define-aplan-predicate requires-access-right (object operation capability) ())

(define-aplan-predicate knows-credentials (attacker user) ())

(define-aplan-predicate is-logged-in (attacker victim-user victim-os victim-machine) ())

(define-aplan-predicate has-remote-shell (attacker victime-machine role) ())

(define-aplan-predicate has-control-of (attacker property process) ())

(define-aplan-predicate controls-process (attacker victim-process how) ())

(define-aplan-predicate has-remote-execution (attacker victim-machine role) ())

(define-aplan-predicate user-forced-to-login (user machine) ())

(define-aplan-predicate modified-by (attacker object) ())
(define-aplan-predicate read-by (attacker object) ())

(define-aplan-predicate malware-installed-on-machine (attacker machine malware) ())

(define-aplan-predicate disk-filled (machine) ())

(define-aplan-predicate unifiable (thing1 thing2) (ji:unification-model non-stateful-predicate-model))

(define-aplan-predicate has-been-modified (thing) ())

;; (define-aplan-predicate has-relevant-capability (user action thing) (non-stateful-predicate-model))

;;; This used to include the path, but no caller actually cared, so I've removed that
(define-aplan-predicate accepts-connection (victim-machine type source-user-or-machine) (non-stateful-predicate-model))

;;; This changes over time
(define-aplan-predicate connection-established (source-machine victim-machine type) ())
(define-aplan-predicate data-exfiltrated (data source-machine victim-machine) ())

(define-aplan-predicate uses-machine (machine user) (non-stateful-predicate-model))

(define-aplan-predicate email-client-of (user email-server) (non-stateful-predicate-model))

(define-aplan-predicate email-sent-to (user attacker foothold-machine foothold-role email-server) ())

(define-aplan-predicate email-received (user email victim-machine) ())

(define-aplan-predicate file-clicked-on (user file application-type) ())

;;; A process is launched on the machine/os running as user launching-source
(define-aplan-predicate process-launched (process machine os user file) ())

;;; This changes over time
(define-aplan-predicate email-submitted (victim-machine kind-of-mail source-machine) ())
(define-aplan-predicate knows-password (attacker victim-user) ())
(define-aplan-predicate knows-key (attacker thing) ())
;;; A generic knows predicate in the form "the attacker knows that the domain passwordd of the domain is <foo>"
(define-aplan-predicate knows (attacker role system thing) ())

;;; These change over time
(define-aplan-predicate software-downloaded (package computer) ())
(define-aplan-predicate software-loaded (package computer) ())

;;; These are static descriptions of the environment
;;; Typically, the DNS translation of a domain name to an IP address
(define-aplan-predicate translation-of (symbolic-rep concrete-rep) (non-stateful-predicate-model))

(define-aplan-predicate path-between (subnet1 subnet2 path) (non-stateful-predicate-model))
 
(define-aplan-predicate reachable-from (computer1 computer2 router) (non-stateful-predicate-model))

(define-aplan-predicate reachable-for-remote-execution (victim-machine attacker protocol) (non-stateful-predicate-model))

(define-aplan-predicate policy-for-bridge (bridge connection-type location-mask) (non-stateful-predicate-model))

(define-aplan-predicate policy-for-host (host connection-type location-mask) (non-stateful-predicate-model))

(define-aplan-predicate protocol-is-relevant-for (goal protocol-name) (non-stateful-predicate-model))

(define-aplan-predicate is-protocol (protocol-name) (non-stateful-predicate-model restorable-predicate))

(define-aplan-predicate port-for-protocol (protocol-name port-number) (non-stateful-predicate-model restorable-predicate))

;;; An example of this: [protocol-for remote-execution remote-shell telnet]
(define-aplan-predicate protocol-for (major-purpose sub-type protocol-name) (non-stateful-predicate-model restorable-predicate))

#+allegro
(excl:def-fwrapper wrap-arglist-2 (symbol)
  (handler-case (excl:call-next-fwrapper)
    (error nil 
      (error "~s  is not a function, macro or predicate" symbol))
    (:no-error (answer &optional flag) (values answer flag))))

#+allegro
(excl:fwrap 'excl:arglist 'wrap-arglist-2 'wrap-arglist-2)






;;; FOR AUTO PILOT EXAMPLE
;;; E.G [IS-PROXIMATE-TO TYPICAL-ATTACKER GPS RADIO-COMMUNICATIO]
(define-aplan-predicate is-proximate-to (attacker victim purpose) (non-stateful-predicate-model))



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Predicates related to busses and switches and connections to them
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-aplan-predicate connected-to (computer interface bus slot) (non-stateful-predicate-model))

(define-aplan-predicate can-master (computer bus) (non-stateful-predicate-model))

(define-aplan-predicate can-be-mastered-by (slave master bus) (non-stateful-predicate-model))

(define-aplan-predicate command-to (peripheral command-name) (non-stateful-predicate-model))

(define-aplan-predicate can-issue-command-to (master victim command bus) (non-stateful-predicate-model))

(define-aplan-predicate system-role (system role-name component) (non-stateful-predicate-model))
