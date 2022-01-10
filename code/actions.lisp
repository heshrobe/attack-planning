;;; -*- Syntax: Joshua; Package: APLAN; syntax: joshua; readtable: Joshua  -*-

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Descriptions of Actions Available to the planner
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


(in-package :aplan)

(define-action connect-via (?current-foothold-computer ?current-foothold-role ?victim-computer ?protocol-name)
  :prerequisites ([accepts-connection ?victim-computer ?protocol-name ?current-foothold-computer]
		  [is-protocol ?protocol-name])
  :post-conditions ([connection-established ?current-foothold-computer ?victim-computer ?protocol-name])
  )

(define-action submit-email (?type-of-email ?process ?foothold-computer ?foothold-role)
  :prerequisites ([current-foothold ?foothold-computer ?foothold-role]
		  [accepts-connection ?victim-computer email ?foothold-computer])
  :post-conditions ([email-submitted ?victim-computer ?type-of-email ?foothold-computer])
  )

;;; Hack: Needs pre-requisites, like has remote execution
;;; on computer that the file lives on


(define-action take-control-with-buffer-overflow (?attacker ?process ?protocol)
  :prerequisites ([is-vulnerable-to ?process buffer-overflow-attack ?protocol])
  :post-conditions ([has-control-of ?attacker execution ?process])
  )


(define-action create-malicious-browser-extension (?attacker ?process ?extension)
  :output-variables (?extension)
  :prerequisites ()
  :outputs ((?extension (make-object 'extension :name (make-name 'extension))))
  )

;;; This should be replaced by the one below and an action to create the phishing email
(define-action send-phishing-email (?attacker ?attacker-foothold-computer ?email-server ?victim ?process)
  :prerequisites ([has-foothold ?email-computer ?sending-computer ?sending-role smtp]
		  [attacker-and-computer ?attacker ?attacker-computer])
  :post-conditions ([email-sent-to ?user ?attacker ?sending-computer ?sending-role ?email-server]
		    [knows-credentials ?attacker ?victim]
		    )
  )

;;; The attacker sends an email from his computer to the email server for eventual
;;; delivery to the victim-computer of the victim-user

(define-action create-email-with-corrupt-attachment (?attacker ?attachment-type ?email-message ?attachment)
  :output-variables (?email-message ?attachment)
  :prerequisites ()
  :outputs ((?attachment (make-object 'application-file :name (make-name 'attachment) :application ?attachment-type))
            (?attachments (list ?attachment))
            (?email-message (make-object 'email-message :name (make-name 'email-message) :attachments ?attachments)))
  :post-conditions ()
  )


(define-action create-email-with-corrupt-link (?attacker ?hyper-link ?email-message)
  :output-variables (?email-message ?hyper-link)
  :prerequisites()
  :outputs ((?hyper-link (make-object 'hyper-link :name (make-name 'hyper-link)))
            (?email-message (make-object 'email-message :name (make-name 'email-message) :attachments ?hyper-link))
            )
  :post-conditions ()
  )

(define-action send-email (?attacker ?email ?sending-computer ?email-server ?victim)
  :bindings ([value-of ?victim.computers ?victim-computer])
  :prerequisites ([has-foothold ?email-server ?sending-computer ?sending-role smtp]
                  [attacker-and-computer ?attacker ?attacker-computer])
  :post-conditions ([email-sent-to ?victim ?attacker ?sending-computer ?sending-role ?email-server]
                    [email-received ?victim ?email ?victim-computer]
		    )
  )

(define-action create-removable-media-with-corrupt-attachment (?attacker ?attachment-type ?removable-media ?attachment)
  :output-variables (?removable-media ?attachment)
  :prerequisites ()
  :outputs ((?attachment (make-object 'application-file :name (make-name 'attachment) :application ?attachment-type))
            (?attachments (list ?attachment))
            (?removable-media (make-object 'removable-media :name (make-name 'removable-media) :attachments ?attachments)))
  :post-conditions ()
  )

(define-action user-clicks-on-attachment (?user ?user-computer ?email-message ?attachment ?new-process)
  :prerequisites ([email-received ?user ?email-message ?user-computer])
  :bindings ([value-of ?email-message.attachments ?attachment]
             [value-of ?attachment.application ?application-type])
  :typing ((?email-message email-message)
           (?attachment application-file))
  :post-conditions ([file-clicked-on ?user ?attachment ?application-type])
  )

(define-action user-uses-removable-media (?user ?user-computer ?removable-media ?attachment ?new-process)
  :prerequisites ()
  :bindings([value-of ?removable-media.attachments ?attachment]
            [value-of ?attachment.application ?application-type])
  :typing ((?removable-media removable-media)
           (?attachment application-file))
  :post-conditions ([file-clicked-on ?user ?attachment ?application-type])
  )

(define-action system-launches-process-for-file (?os ?user-computer ?user ?file ?new-process)
  :prerequisites ([file-clicked-on ?user ?file ?application-type])
  :bindings ([value-of ?file.application ?application-type])
  :typing ((?file application-file))
  :outputs ((?new-process (let ((process-type (smash ?application-type 'process)))
                            (make-object process-type :name (make-name process-type)))))
  :post-conditions ([process-launched ?new-process ?user-computer ?os ?user ?file])
  )

(define-action launch-process (?attacker ?victim-computer ?victim-os ?new-process-type ?new-user ?current-role)
  :prerequisites ([has-remote-execution ?attacker ?victim-computer ?current-role])
  :outputs ((?new-process (make-object 'process :name (make-name 'shell-process))))
  :post-conditions ([process-launched ?new-process ?victim-computer ?victim-os ?new-user ?current-role]))

(define-action login (?attacker ?victim-user ?victim-os-instance ?current-foothold-computer ?current-foothold-role)
  :bindings ([value-of ?victim-os-instance.computer ?victim-computer]
	     [has-foothold ?victim-computer ?current-foothold-computer ?current-foothold-role ?protocol-name]
             )
  :prerequisites ([connection-established ?current-foothold-computer ?victim-computer ?protocol-name]
                  ;; The user has to be an authorized user of the machine.
                  [value-of ?victim-computer.users ?victim-user]

                  [knows-credentials ?attacker ?victim-user]
                  )
  :post-conditions ([is-logged-in ?attacker ?victim-user ?victim-os ?victim-computer])
  )

(define-action login-with-credentials (?victim-user ?victim-os-instance ?from-computer ?from-role ?protocol-name ?credentials)
  :bindings ([value-of ?victim-os-instance.computer ?victim-computer])
  :prerequisites ([connection-established ?from-computer ?victim-computer ?protocol-name]
                  [knows ?from-role credentials ?victim-user ?credentials])
  :post-conditions ([is-logged-in ?from-role ?victim-user ?victim-os-instance ?victim-computer]
                    [has-remote-execution ?from-role ?victim-computer ?victim-user])
  )


;;; This should really be an action with 2 potential outcomes, success and failure
;;; but I haven't yet introduced conditional actions and methods.
;;; For plan recognition it probably doesn't matter
;;; The attacker, acting from its foothold, attempts to login into a victim computer over some protocol
;;; using a white list of user-id password pairs returning the credentials (user-id and password) of a
;;; successful entry on the white list.
;;; The white-list probably doesn't need to be represented here?
(define-action attempt-login (?attacker ?foothold-computer ?victim-computer ?protocol ?credentials)
  :output-variables (?credentials)
  :bindings ((?victim-user ?victim-computer.users)
             (?credentials ?victim-user.credentials))
  :prerequisites ([connection-established ?foothold-computer ?victim-computer ?protocol])
  :post-conditions ([knows ?attacker credentials ?victim-user ?credentials]))

(defrule logged-in-implies-remote-execution (:forward)
  if [in-state [is-logged-in ?attacker ?victim-user ?victim-os ?victim-computer] ?state]
  then  [in-state [has-remote-shell ?attacker ?victim-computer ?victim-user] ?state])

(defrule remote-shell-implies-remote-execution (:forward)
  if [in-state [has-remote-shell ?attacker ?victim-computer ?victim-user] ?state]
  then [in-state [has-remote-execution ?attacker ?victim-computer ?victim-user] ?state]
  )

(defrule process-control-is-remote-execution (:forward)
  if [and [in-state [controls-process ?attacker ?victim-process ?any-means] ?state]
          [object-type-of ?victim-process process]
          [in-state [value-of (?victim-process host-os) ?os-instance] ?state]
          [object-type-of ?os-instance operating-system]
          [in-state [value-of (?os-instance computer) ?victim-computer] ?state]]
  then [in-state [has-remote-execution ?attacker ?victim-computer ?victim-process] ?state]
  )

(define-action launch-code-reuse-attack (?attacker ?victim-process ?protocol ?foothold-computer ?foothold-role)
  :bindings ([current-foothold ?foothold-computer ?foothold-role]
	     [value-of ?victim-process.host-os ?victim-os]
	     [value-of ?victim-os.computer ?victim-computer])
  :prerequisites ([has-foothold ?victim-computer ?foothold-computer ?foothold-role ?protocol]
		  [is-vulnerable-to ?victim-process buffer-overflow-attack ?protocol]
		  [connection-established ?foothold-computer ?victim-computer ?protocol-name])
  :post-conditions ([controls-process ?attacker ?victim-process code-reuse])
  )

(define-action launch-code-injection-attack (?attacker ?victim-process ?protocol ?foothold-computer ?foothold-role)
  :bindings ([current-foothold ?foothold-computer ?foothold-role]
	     [value-of ?victim-process.host-os ?victim-os]
	     [value-of ?victim-os.computer ?victim-computer])
  :prerequisites ([has-foothold ?victim-computer ?foothold-computer ?foothold-role ?protocol]
		  [connection-established ?foothold-computer ?victim-computer ?protocol]
		  [is-vulnerable-to ?victim-process buffer-overflow-attack ?protocol])
  :post-conditions ([has-control-of ?attacker execution ?victim-process]))


;;; This is essentially a no-op if the victim user and the attacker
;;; are the same.
(define-action use-own-password (?victim-user ?victim-computer)
  :bindings ((?victim-os-instance ?victim-computer.os)
             (?pool ?victim-os-instance.authorization-pool)
	     [attacker-and-computer ?attacker ?attacker-computer])
  :prerequisites ([value-of ?victim-os-instance.users ?victim-user]
		  [value-of ?pool.users ?victim-user])
  :post-conditions ([knows-credentials ?attacker ?victim-user])
  )

(define-action guess-password (?attacker ?user ?victim-computer)
  :bindings ([current-foothold ?foothold-computer ?foothold]
	     [protocol-for remote-execution remote-shell ?protocol-name])
  :prerequisites ([connection-established ?foothold-computer ?victim-computer ?protocol-name]
                  [value-of (?user has-weak-password) yes]
                  )
  :post-conditions ([knows-credentials ?attacker ?user]
		    [knows-password ?attacker ?user])
  )

(define-action fill-disk (?attacker ?foothold-computer kill-disk)
  :bindings ([attacker-and-computer ?attacker ?attacker-computer])
  :prerequisites ([has-remote-execution ?attacker ?victim-computer ?role]
		  [Malware-installed-on-computer ?attacker ?victim-computer kill-disk])
  :post-conditions ([disk-filled ?victim-computer])
  )

(defrule sysadmin-forced-to-login (:forward)
  if [and [in-state [disk-filled ?victim-computer] ?state]
	  [named-component ?victim-computer os ?victim-os]
	  [value-of (?victim-os superuser) ?victim-user]
	  [object-type-of ?victim-computer computer]
	  [object-type-of ?victim-os operating-system]
	  ]
  then [in-state [user-forced-to-login ?victim-user ?victim-computer] ?state])

(define-action use-access-right-to-modify (?attacker write ?whose-right ?foothold-computer ?victim-object ?victim-computer)
  :prerequisites ([has-permission ?whose-right write ?victim-object])
  :post-conditions ([modified-by ?attacker ?victim-object])
  )

(define-action read-with-rights-of (?attacker ?user ?victim-object)
  :Prerequisites ([has-permission ?user read ?victim-object])
  :post-conditions ([read-by ?attacker ?victim-object])
  )

;;;; (define-action use-access-right-to-modify (?attacker write ?current-foothold-role ?object)
;;;;   :define-predicate nil
;;;;   :bindings ([current-foothold ?current-foothold-computer ?current-foothold-role])
;;;;   :prerequisites ([has-permission ?current-foothold-role write ?object])
;;;;   :post-conditions ([has-been-modified ?object]))

(define-action download-software (?package ?source-computer ?destination-computer ?role)
  :bindings ([attacker-and-computer ?attacker ?attacker-computer])
  :prerequisites ([has-remote-execution ?attacker  ?destination-computer ?role])
  :post-conditions ([software-downloaded ?package ?victim-computer]
		    ))

(define-action load-software (?package ?victim-computer)
  :bindings ([attacker-and-computer ?attacker ?attacker-computer])
  :prerequisites ([has-remote-execution ?attacker ?victim-computer ?role]
		  [software-downloaded ?package ?victim-computer])
  :post-conditions ([software-loaded ?package ?victim-computer]))


(define-action open-ftp-connection (?user ?from-computer ?to-computer)
  :prerequisites ([accepts-connection ?to-computer ftp ?from-computer])
  :post-conditions ([connection-established ?from-computer ?to-computer ftp]))

(define-action transmit-data (?user ?file ?from-computer ?to-computer)
  :prerequisites ([connection-established ?from-computer ?to-computer ftp])
  :post-conditions ([data-exfiltrated ?file ?user ?from-computer ?to-computer]))

; (define-action install-malware (?attacker ?malware-type ?victim-computer)
;   ;; Probably this should be spelled out more so that he has to have
;   ;; a connection to an outside source of the malware.  But that's a future
;   :define-predicate nil
;   :prerequisites ([has-remote-execution ?attaker ?victim-computer ?as-whom])
;   :post-conditions ([malware-installed-on-computer ?attacker ?victim-computer ?malware-type]))

(define-action capture-password-through-keylogger (?attacker ?victim-user ?victim-computer)
  :prerequisites ([has-remote-execution ?attacker ?victim-computer ?role]
		  [malware-installed-on-computer ?attacker ?victim-computer key-logger]
		  [user-forced-to-login ?victim-user ?victim-computer])
  :post-conditions ([knows-password ?attacker ?victim-user]
                    [knows-credentials ?attacker ?victim-user])
  )

(define-action compress-files (?attacker ?victim-computer ?file1 ?file2 ?new-file ?new-file-type)
  :prerequisites ([has-remote-execution ?attacker ?victim-computer ?role])
  :outputs ((?new-file (create-new-resource (make-name 'compressed-password-file) ?new-file-type ?victim-computer)))
  :post-conditions ([compressed-file-of ?new-file ?file1 ?file2]))

(define-action crack-password (?attacker ?password-files ?victim ?c2-server ?cracker-computer)
  :bindings ((?victim-computer ?victim.computers))
  :prerequisites ([data-exfiltrated ?password-files ? ?victim-computer ?c2-server])
  :typing ((?password-files compressed-password-file))
  :post-conditions ([knows-password ?attacker ?victim]
                    [knows-credentials ?attacker ?victim]
                   )
  )

(define-action modify-data-structures (?process ?data-set ?foothold-computer ?foothold-role)
  :bindings ([attacker-and-computer ?attacker ?])
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

(define-action parse-admin-password (?attacker ?admin-script ?victim ?attacker-computer)
  :typing ((?admin-script admin-script-file)
           (?victim admin-user)
           (?attacker-computer computer))
  :bindings ([attacker-and-computer ?attacker ?attacker-computer])
  :prerequisites ([data-exfiltrated ?admin-script ? ? ?attacker-computer])
  :post-conditions ([knows-password ?attacker ?victim]
                    [knows-credentials ?attacker ?victim]))







;;;  Actions related to control systems

(define-action control (actor network-stack)
  :prerequisites ()
  :post-conditions ()
  )

(define-action make-observation (actor network-traffic subnet)
  :prerequisites ()
  :post-conditions ())

(define-action open-http-connection (actor target)
  :prerequisites ()
  :post-conditions ())

;; (define-action trasmit-data (actor data target))

(define-action issue-false-sensor-data-report (?controller-computer ?victim-computer ?bus ?sensor-type)
  :prerequisites ()
  :post-conditions ()
  )



(define-action goal-already-satisfied (?goal)
  :prerequisites ()
  :post-conditions ()
  )

(define-action drop-dll (?before-file ?dll-file ?after-file)
  :typing ((?before-file file)
           (?dll-file file)
           (?after-file file)
           )
  :bindings ([value-of 
