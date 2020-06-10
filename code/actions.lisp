;;; -*- Syntax: Joshua; Package: APLAN; syntax: joshua; readtable: Joshua  -*-

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Descriptions of Actions Available to the planner
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


(in-package :aplan)

(define-action connect-via (?current-foothold-machine ?current-foothold-role ?victim-machine ?protocol-name)
  :prerequisites ([accepts-connection ?victim-machine ?protocol-name ?current-foothold-machine]
		  [is-protocol ?protocol-name])
  :post-conditions ([connection-established ?current-foothold-machine ?victim-machine ?protocol-name])
  )

(define-action submit-email (?type-of-email ?process ?foothold-machine ?foothold-role)
  :prerequisites ([current-foothold ?foothold-machine ?foothold-role]
		  [accepts-connection ?victim-machine email ?foothold-machine])
  :post-conditions ([email-submitted ?victim-machine ?type-of-email ?foothold-machine])
  )

;;; Hack: Needs pre-requisites, like has remote execution
;;; on machine that the file lives on


(define-action take-control-with-buffer-overflow (?attacker ?process)
  :prerequisites ([is-vulnerable-to ?process buffer-overflow-attack])
  :post-conditions ([has-control-of ?attacker ?process])
  )

(define-action send-phishing-email (?attacker ?attacker-foothold-computer ?email-machine ?victim ?process)
  :prerequisites ([has-foothold ?email-machine ?sending-machine ?sending-role smtp]
		  [attacker-and-machine ?attacker ?attacker-machine])
  :post-conditions ([email-sent-to ?user ?attacker ?sending-machine ?sending-role]
		    [knows-credentials ?attacker ?victim]
		    )
  )

(define-action login (?victim-user ?victim-os-instance ?current-foothold-machine ?current-foothold-role)
  :bindings ([attacker-and-machine ?attacker ?attacker-machine]
	     [current-foothold ?current-foothold-machine ?current-foothold-role]
	     [value-of ?victim-os-instance.machine ?victim-machine])
  :prerequisites ([connection-established ?current-foothold-machine ?victim-machine ?protocol-name]
		  [knows-credentials ?attacker ?victim-user])
  :post-conditions ([is-logged-in ?attacker ?victim-user ?victim-os ?victim-machine])
  )

(defrule logged-in-implies-remote-execution (:forward)
  if [in-state [is-logged-in ?attacker ?victim-user ?victim-os ?victim-machine] ?state]
  then  [in-state [has-remote-shell ?attacker ?victim-machine ?victim-user] ?state])

(defrule remote-shell-implies-remote-execution (:forward)
  if [in-state [has-remote-shell ?attacker ?victim-machine ?victim-user] ?state]
  then [in-state [has-remote-execution ?attacker ?victim-machine ?victim-user] ?state]
  )

(defrule process-control-is-remote-execution (:forward)
  if [in-state [controls-process ?attacker ?victim-process ?any-means] ?state]
  then [in-state [has-remote-execution ?attacker ?victim-machine ?victim-process] ?state]
  )

(define-action launch-code-reuse-attack (?attacker ?victim-process ?protocol ?foothold-machine ?foothold-role)
  :bindings ([current-foothold ?foothold-machine ?foothold-role] 
	     [value-of ?victim-process.host-os ?victim-os]
	     [value-of ?victim-os.machine ?victim-machine])
  :prerequisites ([has-foothold ?victim-process.machine ?foothold-machine ?foothold-role] 
		  [vulnerable-to-overflow-attack ?victim-process]
		  [connection-established ?foothold-machine ?victim-machine ?protocol-name])
  :post-conditions ([controls-process ?attacker ?victim-process code-reuse])
  )

(define-action launch-code-injection-attack (?attacker ?victim-process ?protocol ?foothold-machine ?foothold-role)
  :bindings ([current-foothold ?foothold-machine ?foothold-role]
	     [value-of ?victim-process.host-os ?victim-os]
	     [value-of ?vicim-os.machine ?victim-machine])
  :prerequisites ([has-foothold ?victim-process.machine ?foothold-machine ?foothold-role]
		  [connection-established ?foothold-machine ?victim-machine ?protocol-name]
		  [vulnerable-to-overflow-attack ?victim-process ?protocol])
  :post-conditions ([has-control-of ?attacker ?victim-process]))


;;; This is essentially a no-op if the victim user and the attacker
;;; are the same.
(define-action use-own-password (?victim-user ?victim-machine)
  :bindings ([value-of (?victim-machine os) ?victim-os-instance]
	     [value-of (?victim-os-instance users) ?victim-user]
	     [value-of (?victim-os-instance authorization-pool) ?pool])
  :prerequisites ([unifiable ?victim-user ?victim-machine]
		  [value-of (?pool users) ?victim-user])
  :post-conditions ([knows-credentials ?attacker ?user])
  )

(define-action guess-password (?attacker ?user ?victim-machine)
  :bindings ([current-foothold ?foothold-machine ?foothold]
	     [protocol-for remote-execution remote-shell ?protocol-name])
  :prerequisites ([connection-established ?foothold-machine ?victim-machine ?protocol-name])
  :post-conditions ([knows-credentials ?attacker ?user])
  )

(define-action fill-disk (?attacker ?foothold-machine kill-disk)
  :bindings ([attacker-and-machine ?attacker ?attacker-machine])
  :prerequisites ([has-remote-execution ?attacker ?victim-machine ?role]
		  [Malware-installed-on-machine ?attacker ?victim-machine kill-disk])
  :post-conditions ([disk-filled ?victim-machine])
  )

(defrule sysadmin-forced-to-login (:forward)
  if [and [in-state [disk-filled ?victim-machine] ?state]
	  [named-component ?victim-machine os ?victim-os]
	  [value-of (?victim-os superuser) ?victim-user]
	  [ltms:object-type-of ?victim-machine computer]
	  [ltms:object-type-of ?victim-os operating-system]
	  ]
  then [in-state [user-forced-to-login ?victim-user ?victim-machine] ?state])

(define-action use-access-right-to-modify (?attacker write ?whose-right ?foothold-computer ?victim-object ?victim-machine)
  :define-predicate t
  :prerequisites ([knows-password ?attacker ?whose-right]
		  [has-permission ?whose-right write ?victim-object])
  :post-conditions ([modified-by ?attacker ?victim-object])
  )


;;;; (define-action use-access-right-to-modify (?attacker write ?current-foothold-role ?object)
;;;;   :define-predicate nil
;;;;   :bindings ([current-foothold ?current-foothold-machine ?current-foothold-role])
;;;;   :prerequisites ([has-permission ?current-foothold-role write ?object])
;;;;   :post-conditions ([has-been-modified ?object]))

(define-action download-software (?package ?source-computer ?destination-computer ?role)
  :bindings ([attacker-and-machine ?attacker ?attacker-computer])
  :prerequisites ([current-foothold ?destination-computer ?role])
  :post-conditions ([software-downloaded ?package ?victim-computer]
		    ))


(define-action load-software (?package ?victim-computer)
  :bindings ([attacker-and-machine ?attacker ?attacker-computer])
  :prerequisites ([current-foothold ?victim-computer ?role]
		  [software-downloaded ?package ?victim-computer])
  :post-conditions ([software-loaded ?package ?victim-machine]))


; (define-action install-malware (?attacker ?malware-type ?victim-machine)
;   ;; Probably this should be spelled out more so that he has to have
;   ;; a connection to an outside source of the malware.  But that's a future
;   :define-predicate nil
;   :prerequisites ([has-remote-execution ?attaker ?victim-machine ?as-whom])
;   :post-conditions ([malware-installed-on-machine ?attacker ?victim-machine ?malware-type]))

(define-action capture-password-through-keylogger (?attacker ?victim-user ?victim-machine)
  :prerequisites ([has-remote-execution ?attacker ?victim-machine ?role]
		  [malware-installed-on-machine ?attacker ?victim-machine key-logger]
		  [user-forced-to-login ?victim-user ?victim-machine])
  :post-conditions ([knows-password ?attacker ?victim-user])
  )


  


;;; Actions related to control systems

(define-action control (actor network-stack))

(define-action make-observation (actor network-traffic subnet))

(define-action open-ftp-connection (actor target))

(define-action open-http-connection (actor target))

(define-action trasmit-data (actor data target))

(define-action issue-false-sensor-data-report-to (controller source bus sensor-type))

(define-action uses-control-to-achieve-access-right (attacker right component))