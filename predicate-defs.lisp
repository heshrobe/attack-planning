;;; -*- Syntax: Joshua; Package: APLAN; readtable: Joshua; Mode: Common-lisp  -*-

(in-package :aplan) 

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

(define-predicate accepts-connection (machine type user path) (ltms:ltms-predicate-model))

(define-predicate uses-machine (machine user) (ltms:ltms-predicate-model))

(define-predicate email-client-of (user email-server) (ltms:ltms-predicate-model))

;;; Typically, the DNS translation of a domain name to an IP address
(define-predicate translation-of (symbolic-rep concrete-rep) (ltms:ltms-predicate-model))

(define-predicate connected (subnet1 subnet2 path) (ltms:ltms-predicate-model))
 
(define-predicate reachable-from (computer1 computer2 router) (ltms:ltms-predicate-model))

(define-predicate policy-for (bridge connection-type location-mask) (ltms:ltms-predicate-model))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Predicate defining macros
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


(defmacro define-goal (name variables) `(define-predicate ,name ,(append variables '(plan)) (ltms:ltms-predicate-model)))

;;; (defmacro define-subgoal-with-purpose (name variables) `(define-predicate ,name ,(append variables '(purpose plan)) (ltms:ltms-predicate-model)))

(defparameter *action-table* (make-hash-table))

(defmacro define-action (name variables) `(setf (gethash ',name *action-table*) ',variables))


#+allegro
(def-fwrapper wrap-arglist-2 (symbol)
  (handler-case (excl:call-next-fwrapper)
    (error nil 
      (or
       (gethash symbol *action-table*)
       (error "~s  is not a function, macro or predicate" symbol)))
    (:no-error (answer &optional flag) (values answer flag))))

#+allegro
(fwrap 'arglist 'wrap-arglist-2 'wrap-arglist-2)


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

(define-goal affect (attacker property resource-or-component))

;;; Takes-control-of means to affect the behavior of something either directly or indirectly
(define-goal takes-control-of (attacker component-property component))

;;; Direct control means you actually control the execution of the component
;;; by either running your own code (e.g. code injection attacks)
;;; or by forcing control flow to go to a place that does what you want done (code reuse attacks, e.g.)
(define-goal takes-direct-control-of (attack component-property component))

;;; Indirect control means causing the behavior of the component to change (e.g. through its inputs) but not
;;; causing a change in control flow
(define-goal takes-indirect-control-of (attack component-property component))

;;; Having gained control use it to affect the property of the target
(define-goal use-control-of-to-affect-resource (attacker controlled-thing property resource))

(define-goal force-compilation (attacker source-code-file compiled-code-file))

(define-goal force-load (attacker code target))

;;; Modify some featue of an object
(define-goal modify (attacker object-property object))

;;; Used?
(define-goal modify-contents (attacker thing))

(define-goal achieve-knowledge-of-contents (attacker thing))

;;; achieve knowledge of a victim's password for some entity
(define-goal achieve-knowledge-of-password (attacker victim entity))

(define-goal know (attacker thing property))

(define-goal observe (attacker object property))

(define-goal observe-network-traffic (attacker subnet))

;;; The attacker achieves a particular principal's capability (operation object)
(define-goal achieve-access-right (attacker operation thing principal))
(define-goal use-access-right-to-modify (attacker operation principal thing))

(define-goal make-member-of (attacker thing set))

;;; This implies guess some piece of knowedge like a passwork
(define-goal guess (attacker thing property))

(define-goal guess-password (attacker user resource))

;;; discover the existence of a physical resource (e.g. a machine)
(define-goal discover (attacker thing property))

(define-goal achieve-connection (attacker os-instance connection-type))

;;; Note: Maybe this should specify the entity that's doing the execution
;;; an entity might be a process or a user.  Would need a mixin system-entity
;;; that's mixed into both user and process.
(define-goal remote-execution (attacker entity os-instance))

(define-goal code-injection (attacker process os-instance))

(define-goal code-reuse (attacker process os-instance))

(define-predicate vulnerable-to-overflow-attack (process) (ltms:ltms-predicate-model))

(define-goal remote-shell (attacker user os-instance))

;;; This is related to attacks in which for example the user is misdirected
;;; to a fake site or to a fake DNS resolver
(define-goal cause-to-believe (attacker user thing property))

(define-goal increase-size (attacker thing))

(define-goal decrease-size (attacker thing))


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
                                                     
;;; The actor logs onto the particular OS as user

(define-action login (actor user os-instance))

(define-action use-own-password (user))

(define-action password-dictionary-lookup-attack (actor user))

(define-action social-engineering-attack (actor victim))

(define-action sniff-a-password (actor victim subnet))

(define-action connect-via (actor machine protocol-name))

;;; This seems like a dubious way of saying what we mean
;;; probably the rule is dubious as well
(define-action control (actor network-stack))

(define-action observe (actor network-traffic subnet))

(define-action open-ftp-connection (actor target))

(define-action open-http-connection (actor target))

(define-action trasmit-data (actor data target))

(define-action launch-code-injection-attack (attacker process))

(define-action launch-code-reuse-attack (attacker process))

(define-action issue-false-sensor-data-report (attacker controller source bus))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Predicates related to busses and connections to them
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-predicate connected-to-bus (computer interface bus slot) (ltms:ltms-predicate-model))

(define-predicate can-master (computer bus) (ltms:ltms-predicate-model))

(define-predicate can-be-mastered-by (slave master bus) (ltms:ltms-predicate-model))

(define-predicate command-to (peripheral command-name) (ltms:ltms-predicate-model))

(define-predicate can-issue-command-to (master victim command bus) (ltms:ltms-predicate-model))

(define-predicate system-role (system role-name component) (ltms:ltms-predicate-model))