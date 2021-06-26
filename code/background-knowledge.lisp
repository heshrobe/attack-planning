;;; -*- Syntax: Joshua; Package: APLAN; syntax: joshua; readtable: Joshua  -*-

(in-package :aplan)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Web Server Vulnerabilities
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defrule assume-web-server-not-protected (:forward)
  if [object-type-of ?thing web-server-process]
  then (assume [not [protected-from ?thing buffer-overflow-attack http]]))

(defrule web-server-vulnerable-to-buffer-overflow (:forward)
  If [and [object-type-of ?thing web-server-process]
          [not [protected-from ?thing buffer-overflow-attack http]]]
  then [is-vulnerable-to ?thing buffer-overflow-attack http])

(defun user-ensemble-has-typical-user (user)
  (block exit
    (ask* `[value-of (,user ensemble) ?ensemble]
          (ask* [value-of (?ensemble typical-user) ?typical-user]
                (return-from exit ?typical-user)))
    nil))

(defrule password-is-guessable (:backward)
  :then [has-guessable-password ?user]
  :if [and [value-of (?user guessable-password) ?guessable]
           (not (null ?guessable))])

#|

I think that the above does a better and simpler job of this
(defrule apache-can-be-hacked-1 (:forward)
  if [object-type-of ?process apache-web-server-process]
  then [vulnerable-to-overflow-attack ?process http]
  )

(defrule check-vulnerabiity (:backward)
  then [is-vulnerable-to ?process ?attack]
  if (is-vulnerable-to ?process ?attack))

;;; How to do the supertyping
(defun is-vulnerable-to (process attack)
  (labels ((do-one-type (type)
             (let ((type-name (ji::object-type-name type)))
               (ask `[protected-from ,type-name ,attack]
                    #'(lambda (just)
                        (declare (ignore just))
                        (return-from is-vulnerable-to (values nil))))
               (ask `[vulnerable-to ,type-name ,attack]
                    #'(lambda (just)
                        (declare (ignore just))
                        (return-from is-vulnerable-to (values t))))
               (loop for his-super in (ji::object-type-supertypes type)
                   do (do-one-type his-super)))))
    (let ((his-type (ji::basic-object-type process)))
      (do-one-type his-type))
    nil))

(defrule web-servers-are-vulnerable (:backward)
  then [vulnerable-to web-server-process buffer-overflow-attack]
  if t)

(defrule common-lisp-http-server-is-safe (:backward)
  then [protected-from cl-http-server-process buffer-overflow-attack]
  if t)

;;; This block of stuff is currently a mess and needs fixing

(defattack-method take-control-of-directly
    ;; Takes control of a component to ultimately affect some property of the target
    :to-achieve [take-control-of ?attacker ?component-property ?component]
    :plan (:goal [takes-direct-control-of ?attacker ?component-property ?component])
    :post-conditiond ([has-control-of ?attacker ?component-property ?component])

;;; one way to take direct control of a process is to
;;; first find some way to modify the loadable file so as to affect the property of the target
;;; and then cause the load of the loadable file of the program that's supposed to run in the process

;;; Fix modify
(defattack-method control-process-through-loadable-files
    :to-achieve [takes-direct-control-of ?attacker ?victim-property ?victim]
    :bindings ([value-of ?victim.program ?program]
               [value-of ?program.load-files ?file])
    :typing ((?victim process)
             (?program program)
             (?file dynamically-loadable-code-file))
    :plan (:sequential
           (:goal [modify contents ?file ?input-context])
	   ;; Note: this is a hack right now.  Really it should be a goal which would involve
	   ;; a series of actions to cause the file to get loaded (logging in?, robooting?)
           (:action [load-file ?attacker ?file ?victim]))
    )


;;; Fix
;;; This should reduce to one of the methods used for code-injection or code-reuse

(defattack-method buffer-overflow-can-control-server-processes
    :to-achieve [takes-direct-control-of ?attacker ?process-property ?process]
    ;; :bindings ((?os-instance ?process.host-os])
    :typing ((?process process)
             ;; (?os-instance operating-system)
             )
    :prerequisites ((is-vulnerable-to ?process 'buffer-overflow-attack))
    :plan (:action [take-control-with-buffer-overflow ?attacker ?process])
    )


|#