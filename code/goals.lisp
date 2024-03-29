;;; -*- Syntax: Joshua; Package: APLAN; readtable: Joshua; Mode: Common-lisp  -*-

(in-package :aplan)


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
(define-goal take-control-of (attacker component-property component))

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
;;; given that the attacker has a foothold in some role on some computer
(define-goal modify (object-property object))

;;; Used?
(define-goal modify-contents (attacker thing))

(define-goal achieve-knowledge-of-contents (thing))

;;; achieve knowledge of a victim's password for some entity
(define-goal achieve-knowledge-of-password (attacker victim-user computer))

(define-goal know (attacker thing property))

(define-goal observe (attacker object property))

(define-goal observe-network-traffic (attacker subnet))

;;; Privilege Escalation:
;;; The attacker achieves a particular principal's capability (operation object)
;;; given that he's achieved a foothold in some role on some computer
;;; (the intent is that whatever lateral motion needed has already been done and this
;;;  goal shouldn't be satisfied by doing more)
(define-goal achieve-access-right (operation thing principal)
  :outputs (principal))

;;; This is an action now
;;; (define-goal use-access-right-to-modify (attacker operation principal thing))

(define-goal make-member-of (thing set))

;;; This implies guess some piece of knowedge like a passwork
(define-goal guess (attacker thing property))


;;; discover the existence of a physical resource (e.g. a computer)
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
;;; The first two of these say what computer the attacker is operating from and what role he's operating in
;;; at this point of the reasoning.  The last is a list of other footholds that the attacker might hold
;;; expressed as a list of computer and role pairs.
;;; The victim-computer is the one you're trying to get execution on (input only)
;;; The victime-role is the role (i.e. user or process) on the victim computer that you're trying to achieve (input and more commonly output)

(define-goal achieve-remote-execution (victim-computer victim-role) :outputs (victim-role))

(define-goal achieve-code-injection (process victim-os-instance))

(define-goal achieve-code-reuse (process victim-os-instance))

(define-goal achieve-remote-shell (victim-os-instance user))



;;; This is related to attacks in which for example the user is misdirected
;;; to a fake site or to a fake DNS resolver
(define-goal cause-to-believe (attacker user thing property))

(define-goal increase-size (thing))

(define-goal decrease-size (thing))

;;; Put the computer into an unusable state that requires sysadmin attention
;;;
(define-goal brick-computer (attacker computer))

(define-goal install-malware (attacker server-computer victim-computer malware))

(define-goal install-malware-via-removable-media (attacker removable-media victim-computer malware))

(define-goal get-user-to-click-on (attacker user thing result)
  :outputs (thing result))

(define-goal find-easy-login-target (prober-computer prober victim-enclave report-server protocol-name credentials)
  :outputs (credentials))
(define-goal propagate-easy-login (attacker loader-server vicimt-computer protocol-name credrntials))
(define-goal find-another-potential-victim (current-victim protocol-name other-victim)
  :outputs (other-victim))
(define-goal exfiltrate-data (actor data from-computer to-computer))

;;; These exists so that we can use use a unique attack-id for the methods
;;; that achieve it.  This is all in support of Caldera-integration.
;;; Achieving this concatenates the data from the first file into the concatenate-file
(define-goal dump-password-data-for-cracker (actor data-file cat-file from-computer))
;;; This extracts the relevant entries from the concatenated passwd and shadow files
;;; The extracted data is put into another file and then sent to the hashcat machine
(define-goal extract-password-data-for-cracker (actor cat-file cracker-file from-computer))

;;; Again this is to facilitate the caldera integration.
(define-goal hash-crack-password (attacker victim victim-computer hash-cat-file attacker-computer cracker-computer))

(define-goal persistently-execute (attacker victim victim-computer))

(define-goal achieve-persistent-remote-execution (victim-computer victim-role) :outputs (victim-role))

(define-goal achieve-persistence-on (entity))
