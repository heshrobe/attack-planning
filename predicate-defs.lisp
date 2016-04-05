;;; -*- Syntax: Joshua; Package: APLAN; Mode: JOSHUA; syntax: joshua; readtable: Joshua  -*-

(in-package :aplan) 

(define-predicate desirable-property-of (system property))

;;; This is used in the sense that a process controls a data-set
(define-predicate process-controls-data-set (thing1 thing2))

;;; Some property of one component affects a property of another component of the OS
(define-predicate impacts (feature component property thing os-instance))

(define-predicate input-of (component resource))

(define-predicate output-of (component resource))

(define-predicate residence (thing place))

(define-predicate migrates-from (thing place1 place2 process))

(define-predicate is-a-format-of (thing format-type other-thing))

(define-predicate transforms (process format1 format2))

(define-predicate has-permission (user object operation))

(define-predicate runs-with-permissions-of (process user))

(define-predicate requires-access-right (object operation capability))

(define-predicate vulnerable-to (thing attack))

(define-predicate protected-from (thing attack))

(define-predicate accepts-connection (machine type user path))

(define-predicate uses-machine (machine user))

;;; Typically, the DNS translation of a domain name to an IP address
(define-predicate translation-of (symbolic-rep concrete-rep))

;;; actions

(define-predicate affect (attacker property resource-or-component os-instance plan))

;;; Takes-control-of means to affect the behavior of something either directly or indirectly
;;; In this and related predicates we carry along the property of the ultimate target that we're trying to affect
(define-predicate takes-control-of (attacker component property target plan))

;;; Direct control means you actually control the execution of the component
;;; by either running your own code (e.g. code injection attacks)
;;; or by forcing control flow to go to a place that does what you want done (code reuse attacks, e.g.)
(define-predicate takes-direct-control-of (attack component property target plan))

;;; Indirect control means causing the behavior of the component to change (e.g. through its inputs) but not
;;; causing a change in control flow
(define-predicate takes-indirect-control-of (attack component property target plan))

;;; Having gained direct control use it to affect the property of the target
(define-predicate uses-control-of-component-to-affect-resource (attacker component property target plan))


;;; Modify some featue of an object in order to ultimately affect some property of a target
(define-predicate modify (attacker object-property object property target plan))

(define-predicate achieve-knowledge-of (attacker thing property target plan))

(define-predicate know (attacker thing property target plan))

(define-predicate observe (attacker object property thing plan))

;;; The attacker achieves a particular user's capability (operation object)
(define-predicate achieve-access-right (attacker right thing user property target plan))

(define-predicate make-member-of (attacker thing set property target plan))

(define-predicate guess (attacker thing property target plan))

(define-predicate achieve-connection (attacker os-instance connection-type property target plan))

(define-predicate logon (attacker user os-instance property target plan))

;;; This is related to attacks in which for example the user is misdirected
;;; to a fake site or to a fake DNS resolver
(define-predicate cause-to-believe (attacker user thing property target plan))

(define-predicate connected (subnet1 subnet2 path))
 
(define-predicate reachable-from (computer1 computer2 router))

(define-predicate policy-for (bridge connection-type location-mask))