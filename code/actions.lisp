;;; -*- Syntax: Joshua; Package: APLAN; syntax: joshua; readtable: Joshua  -*-

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Descriptions of Actions Available to the planner
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


(in-package :aplan)

(define-action connect-via (?current-foothold-machine ?current-foothold-role ?victim-machine protocol-name)
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

(define-action phishing-attqck (?attacker ?email-machine ?user ?process)
  :prerequisites ([has-foothold ?email-machine ?role smtp]
		  [current-foothold ?sending-machine ?process]
		  [attacker-and-machine ?attacker ?attacker-machine])
  :post-conditions ([email-sent-to ?user ?attacker ?sending-machine ?process]
		    [knows-credentials ?attacker ?user])
  )

(define-action login (?victim-user ?victim-os-instance ?current-foothold-machine ?current-foothold-role)
  :bindings ([attacker-and-machine ?attacker ?attacker-machine]
	     [ltms:value-of (?victim-os-instance machine) ?victim-machine])
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

(define-action launch-code-injection-attack (?victim-process ?foothold-machine ?foothold-role)
  :bindings ([ltms:value-of (?victim-process host-os) ?victim-os]
	     [ltms:value-of (?victim-os machine) ?victim-machine])
  :prerequisites ([vulnerable-to-overflow-attack ?victim-process]
		  [connection-established ?foothold-machine ?victim-machine ?protocol-name])
  :post-conditions ([controls-process ?attacker ?victim-process code-injection])
  )

(defrule process-control-is-remote-execution (:forward)
  if [in-state [controls-process ?attacker ?victim-process ?any-means] ?state]
  then [in-state [has-remote-execution ?attacker ?victim-machine ?victim-process] ?state]
  )

(define-action launch-code-resuse-attack (?victim-process ?foothold-machine ?foothold-role)
  :bindings ([ltms:value-of (?victim-process host-os) ?victim-os]
	     [ltms:value-of (?victim-os machine) ?victim-machine])
  :prerequisites ([vulnerable-to-overflow-attack ?victim-process]
		  [connection-established ?foothold-machine ?victim-machine ?protocol-name])
  :post-conditions ([controls-process ?attacker ?victim-process code-reuse])
  )


;;; This is essentially a no-op if the victim user and the attacker
;;; are the same.
(define-action use-own-password (?victim-user ?victim-machine)
  :bindings ([ltms:named-part-of (?victim-machine os) ?victim-os-instance]
	     [ltms:value-of (?victim-os-instance users) ?victim-user]
	     [ltms:value-of (?victim-os-instance authorization-pool) ?pool])
  :prerequisites ([unify ?victim-user ?victim-machine]
		  [ltms:value-of (?pool users) ?victim-user])
  :post-conditions ([knows-credentials ?attacker ?user])
  )

(define-action password-dictionary-lookup-attack (?attacker ?user ?victim-machine)
  :bindings ([current-foothold ?foothold-machine ?foothold]
	     [protocol-for remote-execution remote-shell ?protocol-name])
  :prerequisites ([connection-established ?foothold-machine ?victim-machine ?protocol-name])
  :post-conditions ([knows-credentials ?attacker ?user])
  )

(define-action fill-disk (?attacker ?foothold-machine kill-disk)
  :bindings ([attacker-and-machine ?attacker ?attacker-machine])
  :prerequisites ([has-remote-execution ?attacker ?victim-machine ?role]
		  [malware-installed-on-machine ?attacker ?victim-machine kill-disk])
  :post-conditions ([disk-filled ?victim-machine])
  )

(defrule sysadmin-forced-to-login (:forward)
  if [and [in-state [disk-filled ?victim-machine] ?state]
	  [ltms:named-part-of ?victim-machine os ?victim-os]
	  [ltms:value-of (?victim-os superuser) ?victim-user]
	  [ltms:object-type-of ?victim-machine computer]
	  [ltms:object-type-of ?victim-os operating-system]
	  ]
  then [in-state [user-forced-to-login ?victim-user ?victim-machine] ?state])

(define-action use-access-right-to-modify (?attacker write ?whose-right ?victim-object)
  :define-predicate nil
  :prerequisites ([knows-password ?attacker ?whose-right]
		  [has-permission ?whose-right write ?victim-object])
  :post-conditions ([modified-by ?attacker ?victim-object])
  )

;;;; (define-action use-access-right-to-modify (?attacker write ?current-foothold-role ?object)
;;;;   :define-predicate nil
;;;;   :bindings ([current-foothold ?current-foothold-machine ?current-foothold-role])
;;;;   :prerequisites ([has-permission ?current-foothold-role write ?object])
;;;;   :post-conditions ([has-been-modified ?object]))

(define-action install-malware (?attacker ?malware-type ?victim-machine)
  ;; Probably this should be spelled out more so that he has to have
  ;; a connection to an outside source of the malware.  But that's a future
  :define-predicate nil
  :prerequisites ([has-remote-execution ?attaker ?victim-machine ?as-whom])
  :post-conditions ([malware-installed-on-machine ?attacker ?victim-machine ?malware-type]))

(define-action capture-password-through-keylogger (?attacker ?victim-user ?victim-machine)
  :prerequisites ([has-remote-execution ?attacker ?victim-machine ?role]
		  [malware-installed-on-machine ?attacker ?victim-machine key-logger]
		  [user-forced-to-login ?victim-user ?victim-machine])
  :post-conditions ([knows-password ?attacker ?victim-user])
  )



#|

All of the actions in system-dependencies:

[issue-false-sensor-data-report ?controller-machine ?victim-machine ?bus ?signal]
[issue-incorrect-setpoint ?attacker ?machine ?other-machine ?bus]
[signal-noise-injection ?attacker ?machine ?signal]



Initially just make these work in the new framework
Then go back and align with ATT&CK
and break down some of these into more atomic elements
add more predicates so that the post-conditions can be more informative

(define-action load-file (actor file destination)
  :prerequisites ()
  :post-conditions ([file-loaded ?file ?destination])
  )

[add-user-jobs ?attacker ?input]
[modify-in-core-data-structures ?process ?data-set ?foothold-machine ?foothold-role]
[read-with-rights-of ?attacker ?privileged-user ?file]
[open-ftp-connection ?attacker ?attacker-machine]
[trasmit-data ?attacker ?file ?attacker-machine]
[uses-control-to-achieve-access-right ?attacker ?right ?object ?foothold-machine]


[sniff-a-password ?attacker ?user ?subnet]
(sniff-a-passward ?user ?subnet)

[control ?attacker ?network-stack ?attacker-machine]
[observe ?attacker network-traffic ?subnet]
(read-using-process-capability ,?capability ,?vehicle ,?object)

[port-scan ?attacker ?victim-machine ?attacker-machine telnet-ports]

[download-malware-from-source ?attacker ?foothold-machine ?victim-machine mirai-client]
[submit-user-jobs ?entity ?user-job-launch-queue]

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;;  Actions -- These are the actual planning operators that you'd see in STRIPS
;;;             style formulations
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-predicate file-loaded (file destination) (ltms:ltms-predicate-model))

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


;;; This seems like a dubious way of saying what we mean
;;; probably the rule is dubious as well
(define-action control (actor network-stack))

(define-action make-observation (actor network-traffic subnet))

(define-action open-ftp-connection (actor target))

(define-action open-http-connection (actor target))

(define-action trasmit-data (actor data target))

(define-action issue-false-sensor-data-report-to (controller source bus sensor-type))

(define-action uses-control-to-achieve-access-right (attacker right component))



(define-action launch-code-injection-attack (attacker victim-process))

(define-action launch-code-reuse-attack (attacker victim-process foothold-machine foothold-role))

(define-action port-scan (attacker victim-machine attacker-machine ports-or-port-ranges))

(define-action attempt-login-from-whitelist (attacker machine whitelist))

(define-action download-malware-from-source (attacker foothold-machine victim-machine malware-type))



|#