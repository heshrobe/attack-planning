;;; -*- Syntax: Joshua; Package: APLAN; readtable: Joshua; Mode: Common-lisp  -*-

(in-package :aplan) 

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Retellable predicates
;;;
;;; There are some facts about the world that we want to preserve even after
;;; we've cleared the joshua database to clear out an "environment model" 
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
;;; Predicates that are used in the structure of the planner
;;;
;;; These keep track of what footholds the attacker has already achieved 
;;; To prevent trying to get the same foothold twice
;;;
;;; It also keeps track of steps it has taken to try to achieve remote-execution
;;; and to obtain footholds so that it doesn't chain back to trying to trying to 
;;; achieve as a sub-goal the exact same thing it is trying to achieve as a super-goal
;;;
;;; Note: For remote execution, this is the machine we're trying to get execution on
;;;       For foothold, this is the machine we're trying to get a foothold to
;;;       As a result, for foothold query a preceding remote-execution for the same machine
;;;                     is OK.  
;;;                    But for remote execution, a prior foothold entry a prior foothold request 
;;;                    for that machine is indicative of a loop.
;;;                       
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; A predicate that is handled in a special way by the in-state machinery
;;; Typically it has an Ask-datq method and doesn't have an actual interned predication
(define-predicate-model special-stateful-predicate-model () (ltms:ltms-predicate-model))

;;; A predicate that is only asserted in the base environment and never changes state.
;;; These are compiled differenlty by def-attack-method and define-action in
;;; that they aren't embedded in an in-state predication
(define-predicate-model non-stateful-predicate-model () (ltms:ltms-predicate-model))

;;; Current-foothold always occurs within the :bindings clause which wraps it inside an [in-state ... ]
;;; It's always asked
(define-predicate current-foothold (foothold-machine foothold-role) (special-stateful-predicate-model))

;;; Foothold-exists always occurs within the :guards clause which wraps it inside an [in-state ... ]
;;; so this is always asked
(define-predicate foothold-doesnt-exist (victim-machine) (special-stateful-predicate-model))

;;; Has-Foothold will appear in a post-conditions clause which wraps it in an [in-state .... ]
;;; It can be both asserted and queried.
(define-predicate has-foothold (victim-machine foothold-machine foothold-role protocol-name) (special-stateful-predicate-model))

;;; here purpose is either remote-execution or foothold
;;; if it's for a foothold we'll also remember the protocol that that foothold needs to be able
;;; to use to talk to the target
;;; This one is always used inside a [in-state ... ] predication
;;; so the sstate doesn't need to be in the predication
(define-predicate place-already-visited? (machine purpose) (tell-error-model special-stateful-predicate-model))

;;; Place-visited always occurs as a note within the :plan structure and the macro expansion
;;; puts the input and output states into the predication.
(define-predicate place-visited (machine purpose) (special-stateful-predicate-model))


(define-predicate attacker-and-machine (attacker attacker-machine) (special-stateful-predicate-model ltms:ltms-predicate-model))

(define-predicate attacker-download-server (attacker attacker-server-machine) (non-stateful-predicate-model))
(define-predicate attacker-adware-server (attacker attacker-server-machine) (non-stateful-predicate-model))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Factual Predicates -- Describing features of the world
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-predicate desirable-property-of (system property) (non-stateful-predicate-model))

;;; This is used in the sense that a process controls a data-set
(define-predicate process-controls-data-set (thing1 thing2) (non-stateful-predicate-model))

;;; Some property of one component affects a property of another component of the OS
(define-predicate impacts (feature component property thing) (non-stateful-predicate-model))

(define-predicate input-of (component resource) (non-stateful-predicate-model))

(define-predicate output-of (component resource) (non-stateful-predicate-model))

(define-predicate named-component (superpart-object name subpart-object) 
  (ji::named-part-of-mixin ltms:ltms-predicate-model))

(define-predicate component (superpart-object subpart-object) (ji::part-of-mixin ltms:ltms-predicate-model))

(define-predicate value-of (path variable) (ji::slot-value-mixin ltms:ltms-mixin default-protocol-implementation-model))

(define-predicate residence (thing place) (non-stateful-predicate-model))

(define-predicate migrates-from (thing place1 place2 process) (non-stateful-predicate-model))

(define-predicate is-a-format-of (thing format-type other-thing) (non-stateful-predicate-model))

(define-predicate transforms (process format1 format2) (non-stateful-predicate-model))

;;; Fix: Why do I have all three of these?
(define-predicate is-vulnerable-to (process attack) (non-stateful-predicate-model))

(define-predicate vulnerable-to (thing attack) (non-stateful-predicate-model))

(define-predicate vulnerable-to-overflow-attack (process protocol) (ltms:ltms-predicate-model))

(define-predicate vulnerable-to-capec (thing capec cve-number) (ltms:ltms-predicate-model))

(define-predicate is-typical-user (user) (non-stateful-predicate-model))

(define-predicate is-superuser (user machine) (ltms:ltms-predicate-model))

;;; These could change over time (I think)

(define-predicate has-permission (user operation object) (ltms:ltms-predicate-model))

(define-predicate runs-with-permissions-of (process user) (ltms:ltms-predicate-model))

(define-predicate requires-access-right (object operation capability) (ltms:ltms-predicate-model))



(define-predicate protected-from (thing attack) (ltms:ltms-predicate-model))

(define-predicate knows-credentials (attacker user) (ltms:ltms-predicate-model))

(define-predicate is-logged-in (attacker victim-user victim-os victim-machine) (ltms:ltms-predicate-model))

(define-predicate has-remote-shell (attacker victime-machine role) (ltms:ltms-predicate-model))

(define-predicate has-control-of (attacker property process) (ltms:ltms-predicate-model))

(define-predicate controls-process (attacker victim-process how) (ltms:ltms-predicate-model))

(define-predicate has-remote-execution (attacker victim-machine role) (ltms:ltms-predicate-model))

(define-predicate user-forced-to-login (user machine) (ltms:ltms-predicate-model))

(define-predicate modified-by (attacker object) (ltms:ltms-predicate-model))
(define-predicate read-by (attacker object) (ltms:ltms-predicate-model))

(define-predicate malware-installed-on-machine (attacker machine malware) (ltms:ltms-predicate-model))

(define-predicate disk-filled (machine) (ltms:ltms-predicate-model))

(define-predicate unifiable (thing1 thing2) (ji:unification-model non-stateful-predicate-model))

(define-predicate has-been-modified (thing) (ltms:ltms-predicate-model))

;; (define-predicate has-relevant-capability (user action thing) (non-stateful-predicate-model))

;;; This used to include the path, but no caller actually cared, so I've removed that
(define-predicate accepts-connection (victim-machine type source-user-or-machine) (non-stateful-predicate-model))

;;; This changes over time
(define-predicate connection-established (source-machine victim-machine type) (ltms:ltms-predicate-model))
(define-predicate data-exfiltrated (data source-machine victim-machine) (ltms:ltms-predicate-model))

(define-predicate uses-machine (machine user) (non-stateful-predicate-model))

(define-predicate email-client-of (user email-server) (non-stateful-predicate-model))

(define-predicate email-sent-to (user attacker foothold-machine foothold-role email-server) (ltms:ltms-predicate-model))

(define-predicate email-received (user email victim-machine) (ltms:ltms-predicate-model))

(define-predicate file-clicked-on (user file application-type) (ltms:ltms-predicate-model))

(define-predicate process-launched (process machine os user file) (ltms:ltms-predicate-model))

;;; This changes over time
(define-predicate email-submitted (victim-machine kind-of-mail source-machine) (ltms:ltms-predicate-model))
(define-predicate knows-password (attacker victim-user) (ltms:ltms-predicate-model))

;;; These change over time
(define-predicate software-downloaded (package computer) (ltms:ltms-predicate-model))
(define-predicate software-loaded (package computer) (ltms:ltms-predicate-model))

;;; These are static descriptions of the environment
;;; Typically, the DNS translation of a domain name to an IP address
(define-predicate translation-of (symbolic-rep concrete-rep) (non-stateful-predicate-model))

(define-predicate path-between (subnet1 subnet2 path) (non-stateful-predicate-model))
 
(define-predicate reachable-from (computer1 computer2 router) (non-stateful-predicate-model))

(define-predicate reachable-for-remote-execution (victim-machine attacker protocol) (non-stateful-predicate-model))

(define-predicate policy-for-bridge (bridge connection-type location-mask) (non-stateful-predicate-model))

(define-predicate policy-for-host (host connection-type location-mask) (non-stateful-predicate-model))

(define-predicate protocol-is-relevant-for (goal protocol-name) (non-stateful-predicate-model))

(define-predicate is-protocol (protocol-name) (non-stateful-predicate-model restorable-predicate))

(define-predicate port-for-protocol (protocol-name port-number) (non-stateful-predicate-model restorable-predicate))

;;; An example of this: [protocol-for remote-execution remote-shell telnet]
(define-predicate protocol-for (major-purpose sub-type protocol-name) (non-stateful-predicate-model restorable-predicate))

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
(define-predicate is-proximate-to (attacker victim purpose) (non-stateful-predicate-model))



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Predicates related to busses and switches and connections to them
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-predicate connected-to (computer interface bus slot) (non-stateful-predicate-model))

(define-predicate can-master (computer bus) (non-stateful-predicate-model))

(define-predicate can-be-mastered-by (slave master bus) (non-stateful-predicate-model))

(define-predicate command-to (peripheral command-name) (non-stateful-predicate-model))

(define-predicate can-issue-command-to (master victim command bus) (non-stateful-predicate-model))

(define-predicate system-role (system role-name component) (non-stateful-predicate-model))

#|

Sample of what the new type of action definition would be
The interpreter i.e. expansion of defaction-method would have to invoke this rule in every plan
that has an action relevant code is in rebuild plan structure

(define-action signal-noise-injection (attacker sensor signal)
  (tell `[in-state [signal-noise-injection ?attacker ?signal ?sensor] ?output-state])
  )

|#