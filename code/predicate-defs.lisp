;;; -*- Syntax: Joshua; Package: APLAN; readtable: Joshua; Mode: Common-lisp  -*-

(in-package :aplan) 

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Predicates that are used in the structure of the planner
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-predicate current-foothold (input-context foothold-machine foothold-role) (ltms:ltms-predicate-model))
(define-predicate foothold-exists (input-context foothold-machine) (ltms:ltms-predicate-model))
(define-predicate has-foothold (input-context new-foothold-machine new-foothold-role output-context) (ltms:ltms-predicate-model))

(define-predicate place-already-visited? (input-context machine protocol) (ltms:ltms-predicate-model))
(define-predicate note-place-visited (input-context machine protocol output-context) (ltms:ltms-predicate-model))

(define-predicate attacker-and-machine (input-context attacker attacker-machine) (ltms:ltms-predicate-model))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Factual Predicates -- Describing features of the world
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-predicate desirable-property-of (system property) (ltms:ltms-predicate-model))

;;; This is used in the sense that a process controls a data-set
(define-predicate process-controls-data-set (thing1 thing2) (ltms:ltms-predicate-model))

;;; Some property of one component affects a property of another component of the OS
(define-predicate impacts (feature component property thing) (ltms:ltms-predicate-model))

(define-predicate input-of (component resource) (ltms:ltms-predicate-model))

(define-predicate output-of (component resource) (ltms:ltms-predicate-model))

(define-predicate residence (thing place) (ltms:ltms-predicate-model))

(define-predicate migrates-from (thing place1 place2 process) (ltms:ltms-predicate-model))

(define-predicate is-a-format-of (thing format-type other-thing) (ltms:ltms-predicate-model))

(define-predicate transforms (process format1 format2) (ltms:ltms-predicate-model))

(define-predicate has-permission (user object operation) (ltms:ltms-predicate-model))

(define-predicate runs-with-permissions-of (process user) (ltms:ltms-predicate-model))

(define-predicate requires-access-right (object operation capability) (ltms:ltms-predicate-model))

(define-predicate vulnerable-to (thing attack) (ltms:ltms-predicate-model))

(define-predicate protected-from (thing attack) (ltms:ltms-predicate-model))

;;; This used to include the path, but no caller actually cared, so I've removed that
(define-predicate accepts-connection (victim-machine type source-user-or-machine) (ltms:ltms-predicate-model))

(define-predicate uses-machine (machine user) (ltms:ltms-predicate-model))

(define-predicate email-client-of (user email-server) (ltms:ltms-predicate-model))

;;; Typically, the DNS translation of a domain name to an IP address
(define-predicate translation-of (symbolic-rep concrete-rep) (ltms:ltms-predicate-model))

(define-predicate path-between (subnet1 subnet2 path) (ltms:ltms-predicate-model))
 
(define-predicate reachable-from (computer1 computer2 router) (ltms:ltms-predicate-model))

(define-predicate reachable-for-remote-execution (victim-machine attacker protocol) (ltms:ltms-predicate-model))

(define-predicate policy-for-bridge (bridge connection-type location-mask) (ltms:ltms-predicate-model))

(define-predicate policy-for-host (host connection-type location-mask) (ltms:ltms-predicate-model))

(define-predicate protocol-is-relevant-for (goal protocol-name))
(define-predicate is-protocol (protocol-name))
(define-predicate port-for-protocol (protocol-name port-number))

(define-predicate protocol-for-remote-execution (execution-type protocol-name) (ltms:ltms-predicate-model))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Predicate defining macros
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


(defmacro define-goal (name variables) `(define-predicate ,name ,(append variables '(input-context output-context plan)) (ltms:ltms-predicate-model)))

;;; (defmacro define-subgoal-with-purpose (name variables) `(define-predicate ,name ,(append variables '(purpose plan)) (ltms:ltms-predicate-model)))

(defparameter *action-table* (make-hash-table))

(defmacro define-action (name variables) `(setf (gethash ',name *action-table*) '(,@variables input-context output-context)))

(defmacro define-protcol (name port)
  `(with-atomic-action
       (tell [is-protocol ,name])
     (tell [port-for-protocol ,port])))

#+allegro
(excl:def-fwrapper wrap-arglist-2 (symbol)
  (handler-case (excl:call-next-fwrapper)
    (error nil 
      (or
       (gethash symbol *action-table*)
       (error "~s  is not a function, macro or predicate" symbol)))
    (:no-error (answer &optional flag) (values answer flag))))

#+allegro
(excl:fwrap 'excl:arglist 'wrap-arglist-2 'wrap-arglist-2)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Goal predicates -- Things we want to achieve through a plan
;;;  Goals with purpose carry an extra argument which is the ultimate
;;;  purpose of the goal
;;;
;;;   These are all defined through macros that hides the last
;;;   argument which is the plan found to achieve this goal
;;;   and the "purpose" which is the next to last argument
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-goal affect (property resource-or-component))

;;; Takes-control-of means to affect the behavior of something either directly or indirectly
(define-goal takes-control-of (attacker component-property component))

;;; Direct control means you actually control the execution of the component
;;; by either running your own code (e.g. code injection attacks)
;;; or by forcing control flow to go to a place that does what you want done (code reuse attacks, e.g.)
(define-goal takes-direct-control-of (attacker component-property component))

;;; Indirect control means causing the behavior of the component to change (e.g. through its inputs) but not
;;; causing a change in control flow
(define-goal takes-indirect-control-of (attacker component-property component))

;;; Having gained control use it to affect the property of the target
(define-goal use-control-of-to-affect-resource (attacker controlled-thing property resource))

(define-goal force-compilation (attacker source-code-file compiled-code-file))

(define-goal force-load (attacker code target))

;;; Modify some featue of an object
;;; given that the attacker has a foothold in some role on some machine
(define-goal modify (object-property object))

;;; Used?
(define-goal modify-contents (attacker thing))

(define-goal achieve-knowledge-of-contents (thing))

;;; achieve knowledge of a victim's password for some entity
(define-goal achieve-knowledge-of-password (attacker victim entity current-foothold))

(define-goal know (attacker thing property))

(define-goal observe (attacker object property))

(define-goal observe-network-traffic (attacker subnet))

;;; Privilege Escalation:
;;; The attacker achieves a particular principal's capability (operation object) 
;;; given that he's achieved a foothold in some role on some machine
;;; (the intent is that whatever lateral motion needed has already been done and this
;;;  goal shouldn't be satisfied by doing more)
(define-goal achieve-access-right (operation thing principal))
(define-goal use-access-right-to-modify (attacker operation principal thing foothold-machine foothold-role other-footholds))

(define-goal make-member-of (thing set))

;;; This implies guess some piece of knowedge like a passwork
(define-goal guess (attacker thing property))

(define-goal guess-password (attacker user resource victim-machine))

;;; discover the existence of a physical resource (e.g. a machine)
(define-goal discover (attacker thing property))

;;; This predicate is the bedrock of lateral motion:
;;; This takes:
;;; 1) The attacker
;;; 2) The path that's he's explored so far.  A list of pairs of foothold and role on the foothold
;;;    The first item in this list is the current foothold and role that he's trying to move from
;;; 3) The victim-os that's his target
;;; 4) The connection type
;;; The last two arguments are bound for the caller to provide information about
;;; Where and in what role the attacker has a foothold.
;;; 5) The Next to last argument is bound for the caller and is the last foothold
;;; 6) The Last argument is bound for the caller and is the role achieved on the foothold
(define-goal get-foothold (victim-os connection-type))
;;; Once the attacker has an appropriate foothold it needs to actually make the connection
;;; While this won't involve any further lateral motion and therefore doesn't need the path-so-far
;;; It still might involve several steps (e.g. aquire credentials connect over telnet login)
(define-goal make-connection (victim connection-type))

;;; This is called with the last three arguments describing the attacker's footholds.
;;; The first two of these say what machine the attacker is operating from and what role he's operating in
;;; at this point of the reasoning.  The last is a list of other footholds that the attacker might hold
;;; expressed as a list of machine and role pairs.
;;; The victim-machine is the one you're trying to get execution on (input only)
;;; The victime-role is the role (i.e. user or process) on the victim machine that you're trying to achieve (input and more commonly output)

(define-goal achieve-remote-execution (victim-machine victim-role))

(define-goal achieve-code-injection (process victim-os-instance))

(define-goal achieve-code-reuse (process victim-os-instance))

(define-goal achieve-remote-shell (victim-os-instance user))

(define-predicate vulnerable-to-overflow-attack (process) (ltms:ltms-predicate-model))

;;; This is related to attacks in which for example the user is misdirected
;;; to a fake site or to a fake DNS resolver
(define-goal cause-to-believe (attacker user thing property))

(define-goal increase-size (thing))

(define-goal decrease-size (thing))

;;; Put the machine into an unusable state that requires sysadmin attention
;;; 
(define-goal brick-machine (attacker machine))

(define-goal install-malware (attacker machine malware))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;;  Actions -- These are the actual planning operators that you'd see in STRIPS
;;;             style formulations
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-action load-file (actor file destination))

(define-action take-control-with-buffer-overflow (actor process))

(define-action add-user-jobs (actor workload))

(define-action modify-in-core-data-structures (actor data-structure))
                                                     
;;; The actor reads the file using the capabilities of the user
(define-action read-with-rights-of (actor user file))
                                                     
;;; The actor logs onto the particular OS as user using this protocol

(define-action login (actor user os-instance foothold-machine protocol))

(define-action use-own-password (user))

(define-action password-dictionary-lookup-attack (actor user))

(define-action social-engineering-attack (actor victim))

(define-action sniff-a-password (actor victim subnet))

(define-action connect-via (actor at-location machine protocol-name))

;;; This seems like a dubious way of saying what we mean
;;; probably the rule is dubious as well
(define-action control (actor network-stack))

(define-action observe (actor network-traffic subnet))

(define-action open-ftp-connection (actor target))

(define-action open-http-connection (actor target))

(define-action trasmit-data (actor data target))

(define-action launch-code-injection-attack (process))

(define-action launch-code-reuse-attack (process))

(define-action issue-false-sensor-data-report-to (attacker controller source bus sensor-type))

(define-action uses-control-to-achieve-access-right (attacker right component))

(define-action submit-email (attacker kind-of-email process foothold-machine foothold-role))

(define-action launch-code-injection-attack (attacker victim-process foothold-machine foothold-role other-footholds))

(define-action launch-code-reuse-attack (attacker victim-process foothold-machine foothold-role other-footholds))

(define-action port-scan (attacker victim-machine attacker-machine ports-or-port-ranges))

(define-action attempt-login-from-whitelist (attacker machine whitelist))

(define-action download-malware-from-source (attacker foothold-machine victim-machine malware-type))


;;; FOR AUTO PILOT EXAMPLE
;;; E.G [IS-PROXIMATE-TO TYPICAL-ATTACKER GPS RADIO-COMMUNICATIO]
(define-predicate is-proximate-to (attacker victim purpose))



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Predicates related to busses and switches and connections to them
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-predicate connected-to (computer interface bus slot) (ltms:ltms-predicate-model))

(define-predicate can-master (computer bus) (ltms:ltms-predicate-model))

(define-predicate can-be-mastered-by (slave master bus) (ltms:ltms-predicate-model))

(define-predicate command-to (peripheral command-name) (ltms:ltms-predicate-model))

(define-predicate can-issue-command-to (master victim command bus) (ltms:ltms-predicate-model))

(define-predicate system-role (system role-name component) (ltms:ltms-predicate-model))

(define-action signal-noise-injection (attacker sensor signal))