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


(define-action take-control-with-buffer-overflow (?attacker ?process ?protocol)
  :prerequisites ([is-vulnerable-to ?process buffer-overflow-attack ?protocol])
  :post-conditions ([has-control-of ?attacker execution ?process])
  )

;;; This should be replaced by the one below and an action to create the phishing email
(define-action send-phishing-email (?attacker ?attacker-foothold-computer ?email-server ?victim ?process)
  :prerequisites ([has-foothold ?email-machine ?sending-machine ?sending-role smtp]
		  [attacker-and-machine ?attacker ?attacker-machine])
  :post-conditions ([email-sent-to ?user ?attacker ?sending-machine ?sending-role ?email-server]
		    [knows-credentials ?attacker ?victim]
		    )
  )

;;; The attacker sends an email from his machine to the email server for eventual
;;; delivery to the victim-machine of the victim-user

(define-action create-email-with-corrupt-attachment (?attacker ?attachment-type ?email-message ?attachment)
  :prerequisites ()
  :outputs ((?attachment (make-object 'application-file :name (make-name 'attachment) :application ?attachment-type))
            (?attachments (list ?attachment))
            (?email-message (make-object 'email-message :name (make-name 'email-message) :attachments ?attachments)))
  :post-conditions ()
  )

(define-action send-email (?attacker ?email ?sending-machine ?email-server ?victim)
  :bindings ([value-of ?victim.machines ?victim-machine])
  :prerequisites ([has-foothold ?email-server ?sending-machine ?sending-role smtp]
                  [attacker-and-machine ?attacker ?attacker-machine])
  :post-conditions ([email-sent-to ?victim ?attacker ?sending-machine ?sending-role ?email-server]
                    [email-received ?victim ?email ?victim-machine]
		    )
  )

(define-action user-clicks-on-attachment (?user ?user-machine ?email-message ?attachment ?new-process)
  :prerequisites ([email-received ?user ?email-message ?user-machine])
  :bindings ([value-of ?email-message.attachments ?attachment]
             [value-of ?attachment.application ?application-type])
  :typing ((?email-message email-message)
            (?attachment application-file))
  :post-conditions ([file-clicked-on ?user ?attachment ?application-type])
  )

(define-action system-launches-process-for-file (?os ?user-machine ?user ?file ?new-process)
  :prerequisites ([file-clicked-on ?user ?file ?application-type])
  :bindings ([value-of ?file.application ?application-type])
  :typing ((?file application-file))
  :outputs ((?new-process (let ((process-type (smash ?application-type 'process)))
                            (make-object process-type :name (make-name process-type)))))
  :post-conditions ([process-launched ?new-process ?user-machine ?os ?user ?file])
  )

(define-action launch-process (?attacker ?victim-machine ?victim-os ?new-process-type ?new-user ?current-role)
  :prerequisites ([has-remote-execution ?attacker ?victim-machine ?current-role])
  :outputs ((?new-process (make-object 'process :name (make-name 'shell-process))))
  :post-conditions ([process-launched ?new-process ?victim-machine ?victim-os ?new-user ?current-role]))

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
  if [and [in-state [controls-process ?attacker ?victim-process ?any-means] ?state]
          [object-type-of ?victim-process process]
          [in-state [value-of (?victim-process host-os) ?os-instance] ?state]
          [object-type-of ?os-instance operating-system]
          [in-state [value-of (?os-instance machine) ?victim-machine] ?state]]
  then [in-state [has-remote-execution ?attacker ?victim-machine ?victim-process] ?state]
  )

(define-action launch-code-reuse-attack (?attacker ?victim-process ?protocol ?foothold-machine ?foothold-role)
  :bindings ([current-foothold ?foothold-machine ?foothold-role] 
	     [value-of ?victim-process.host-os ?victim-os]
	     [value-of ?victim-os.machine ?victim-machine])
  :prerequisites ([has-foothold ?victim-machine ?foothold-machine ?foothold-role ?protocol] 
		  [is-vulnerable-to ?victim-process buffer-overflow-attack ?protocol]
		  [connection-established ?foothold-machine ?victim-machine ?protocol-name])
  :post-conditions ([controls-process ?attacker ?victim-process code-reuse])
  )

(define-action launch-code-injection-attack (?attacker ?victim-process ?protocol ?foothold-machine ?foothold-role)
  :bindings ([current-foothold ?foothold-machine ?foothold-role]
	     [value-of ?victim-process.host-os ?victim-os]
	     [value-of ?victim-os.machine ?victim-machine])
  :prerequisites ([has-foothold ?victim-machine ?foothold-machine ?foothold-role ?protocol]
		  [connection-established ?foothold-machine ?victim-machine ?protocol]
		  [is-vulnerable-to ?victim-process buffer-overflow-attack ?protocol])
  :post-conditions ([has-control-of ?attacker execution ?victim-process]))


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
  :post-conditions ([knows-credentials ?attacker ?user]
		    [knows-password ?attacker ?user])
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
  :prerequisites ([has-permission ?whose-right write ?victim-object])
  :post-conditions ([modified-by ?attacker ?victim-object])
  )

(define-action read-with-rights-of (?attacker ?user ?victim-object)
  :Prerequisites ([has-permission ?user read ?victim-object])
  :post-conditions ([read-by ?attacker ?victim-object])
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


(define-action open-ftp-connection (?user ?from-machine ?to-machine)
  :prerequisites ([accepts-connection ?to-machine ftp ?from-machine])
  :post-conditions ([connection-established ?from-machine ?to-machine ftp]))
                   
(define-action trasmit-data (?user ?file ?from-machine ?to-machine)
  :prerequisites ([connection-established ?from-machine ?to-machine ftp])
  :post-conditions ([data-exfiltrated ?file ?from-machine ?to-machine]))

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

(define-action modify-data-structures (?process ?data-set ?foothold-machine ?foothold-role)
  :bindings ([attacker-and-machine ?attacker ?])
  :prerequisites ([has-control-of ?attacker execution ?process])
  :post-conditions ([modified-by ?attacker ?data-set])
  )




;;; actions for scanning something for a particular type of thing

(define-action scan (?attacker ?collection ?relationship ?result)
  :typing ((?collection collection))
  :bindings ([value-of (?collection owner) ?system]
             [system-role ?system ?relationship ?result])
  :Post-conditions ([knows ?attacker ?relationship ?collection ?result]))

(define-action decrypt (?attacker ?object ?key ?decrypted-thing)
  :prerequisites ([system-role ?object key-for ?key])
  :outputs ((?decrypted-thing (make-object (type-of ?object) :name (make-name (role-name ?object)))))
  :post-conditions ([knows ?attacker decryped-value ?object ?decrypted-thing]))
  




;;;  Actions related to control systems

(define-action control (actor network-stack))

(define-action make-observation (actor network-traffic subnet))

(define-action open-ftp-connection (actor target))

(define-action open-http-connection (actor target))

(define-action trasmit-data (actor data target))

(define-action issue-false-sensor-data-report (?controller-machine ?victim-machine ?bus ?sensor-type)
  :prerequisites ()
  :post-conditions ()
  )


