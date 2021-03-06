;;; -*- Syntax: Joshua; Package: APLAN; syntax: joshua; readtable: Joshua  -*-

(in-package :aplan)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Descriptions of How to hack a system
;;; Returns a nested plan structure (through unification)
;;; consisting of :sequential/:parallel groupings
;;; of (:goal ... :plan ...) structures
;;; and (:action ... structures
;;;
;;; Note: Several of the operators could take advantage of the guards field
;;; rather than the pre-requisite.  Guards get tested before bindings are done
;;; but they might need to do some of their own binding
;;;
;;;
;;;
;;; the top level queries
;;;
;;; Any desirable property
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; This is set up to attack a desirable property of any computer resource?
;;; But the component it goes after is part of the OS.
;;; So this is one method, not the only.  It's the generic method that says
;;; go after some piece of the OS that can affect the desirable property of the victim.
;;; For example, if the victim is a web-server and the goal is to affect its data-privacy
;;; then one way you might go after this is to get hold of some piece of the os and use
;;; that to violate the web-server's data-privacy.
;;; But, there are other methods: for example penetrate some component of the web-server
;;; and use that to violate data-privacy.

(defattack-method affect-property-by-controlling-impacting-component
    :to-achieve [affect ?desirable-property ?victim]
    ;; find some component of the OS of a machine that the victim runs on
    :bindings ([component ?victim.machines.os ?component]
	       [current-foothold ?foothold-machine ?foothold-role]
	       [attacker-and-machine ?attacker ?attacker-machine])
    :typing ((?victim computer-resource)
	     (?component process))
    :prerequisites ([impacts ?component-property ?component ?desirable-property ?victim])
    :plan (:sequential
           ;; this breaks down into two steps:
           ;; 1) Get control of some component of the victim
           ;; 2) Use that control to affect the property of the victim
           ;; Notice that the first step is oblivous to its purpose
           ;; This certainly makes things simpler but might lead to getting control in a way
           ;; that doesn't actually work
           (:goal [take-control-of ?attacker ?component-property ?component])
           (:goal [use-control-of-to-affect-resource ?attacker ?component ?desirable-property ?victim]))
    )

(defattack-method affect-property-by-affecting-input
    :to-achieve [affect ?desirable-property ?victim]
    :prerequisites ([impacts ?resource-property ?resource ?desirable-property ?victim])
    :bindings ([attacker-and-machine ?attacker ?attacker-machine])
    :typing ((?resource computer-resource))
    :plan (:goal [affect ?resource-property ?resource])
    )



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Performance
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; ToDo: More lateral motion stuff
;;; When you do the achieve connection, you need to know what protocols
;;; might be useful.  So we condition this by using protocol-is-relevant-for
;;; need to do more of that.


;;; Note: This could be done more indirectly by saying that
;;; performance is inversely proportional to workload size
;;; and then having a rule that says that to decrease something that
;;; is inversely proportional to something else increaese the something else

(defattack-method increase-workload-to-decrease-performance
    :to-achieve [affect performance ?process]
    :prerequisites ([desirable-property-of ?process performance])
    :bindings ([protocol-is-relevant-for workload-size ?protocol]
	       [attacker-and-machine ?attacker  ?attacker-machine])
    :typing ((?process process)
             (?process.host.os.machine computer)
	     (?process.host-os operating-system)
	     (?process.host-os.workload os-workload))
    :plan (:sequential
	   (:goal [get-foothold ?process.host.os.machine ?protocol])
	   (:goal [increase-size ?process.host-os.workload]))
    )

(defattack-method send-lots-of-emails
    :to-achieve [affect performance ?process]
    :prerequisites ([desirable-property-of ?process performance])
    :bindings ([current-foothold ?foothold-machine ?foothold-role]
	       [attacker-and-machine ?attacker ?attacker-machine])
    :typing ((?process email-server-process)
	     (?foothold-machine computer)
	     )
    :plan (:sequential
	   (:goal [get-foothold ?process.host-os.machine email])
	   (:repeated-action [submit-email ?attacker large-email ?process ?foothold-machine ?foothold-role]))
    :post-conditions ([current-foothold ?foothold-context ?foothold-machine ?foothold-role])
    )

;;; now what we want to say is:
;;; Either
;;; 1) find a process in the current workload that is capable of launching new jobs
;;; get control of that process and cause it launch jobs.  For example, a server that takes
;;; requests through some protocol and launches jobs in response (e.g. web server ftp server)
;;; repeatedly connect to it and cause it to launch a job
;;; 2) Increase the size of the job launch queue

(defattack-method increase-workload-by-increasing-job-launch-queue
    :to-achieve [increase-size ?workload]
    :bindings ([current-foothold ?foothold-machine ?foothold-role])
    :typing ((?workload os-workload))
    :plan (:goal [increase-size ?workload.os.job-launch-queue.user-job-launch-request-queue]))



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Data Privacy
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defattack-method read-resource-property-directly
    :to-achieve [affect data-privacy ?resource]
    :prerequisites ([desirable-property-of ?resource data-privacy])
    :typing ((?resource data-resource))
    :plan (:goal [achieve-knowledge-of-contents ?resource])
    )


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Data Integrity
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; Fix: Need to do an get-foothold to get foothold
(defattack-method write-file-property-directly
    :to-achieve [affect data-integrity ?file]
    :typing ((?file file))
    :prerequisites ([desirable-property-of ?file data-integrity])
    :plan (:goal [modify contents ?file])
    )

;;; To affect the data-integrity of some data-set
;;; Get control of a process that produces the data-set
(defattack-method mung-process-output
    :to-achieve [affect data-integrity ?data-set]
    :bindings ([output-of ?process ?data-set]
	       [attacker-and-machine ?attacker ?attacker-machine])
    :typing ((?process process))
    :plan (:sequential
           (:goal [take-control-of ?attacker data-integrity ?process])
           (:goal [use-control-of-to-affect-resource ?attacker ?process data-integrity ?data-set]))
    )

(defattack-method mung-database
    :to-achieve [affect data-integrity ?database]
    :bindings ([current-foothold ?current-foothold-machine ?current-foothold-role] )
    :typing ((?database database)
             (?current-foothold-role attacker))
    ;; This is wrong.
    ;; We need to find out who has permission to make a
    :prerequisites ()
    :plan (:sequential
	   ;; Also note that it returns in a state where you have remote-execution on the new-foothold-machine
           ;; And you've opened a connecion to the victim machine
	   (:goal [get-foothold ?database.machines database-protocol])
           (:bind [current-foothold ?new-foothold-machine ?new-foothold-role])
	   (:goal [modify data-integrity ?database]))
    )

(defattack-method actually-make-connection
    :to-achieve [make-connection ?victim-machine ?connection-type]
    :bindings ([current-foothold ?current-foothold-machine ?current-foothold-role])
    :plan (:action [connect-via ?current-foothold-machine ?current-foothold-role ?victim-machine ?connection-type])

    )


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Direct Control
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;





;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Indirect Control
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defattack-method take-control-of-indirectly
    :to-achieve [take-control-of ?attacker ?victim-property ?victim]
    :plan (:goal [takes-indirect-control-of ?attacker ?victim-property ?victim])
    :post-conditions ([has-control-of ?attacker ?victim-property ?victim]))

;;; Find an input of the victim and modify its contents
;;; probably should say that the behavior is affected by the content
;;; Fix modify
(defattack-method control-component-through-input
    :to-achieve [takes-indirect-control-of ?attacker ?victim-property ?victim]
    ;; assumption is that we know thing
    :bindings ([input-of ?thing ?input])
    :plan (:goal [modify contents ?input])
    :post-conditions ([has-control-of ?attacker ?victim-property ?victim])
    )


;;; want to say that if the property is affected by the size of the input
;;; then change the size of the input

;;; fix modify
(defattack-method control-component-through-input-size
    :to-achieve [takes-indirect-control-of ?attacker ?victim-property ?victim]
    ;; assumption is that we know thing
    :prerequisites ([impacts size ?input ?victim-property ?victim])
    :bindings ([input-of ?victim ?input])
    :plan (:goal [modify size ?input])
    )


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;;  Modification
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


;;; Note: Should this maybe be broken into two parts:
;;; 1) achieve ability to modify something
;;; 2) Modify it in a way that affects the victim's property
(defattack-method modify-through-part
    :to-achieve [modify ?victim-property ?victim]
    :typing ()
    :bindings ([component ?victim ?component])
    :prerequisites ([impacts ?component-property ?component ?victim-property ?victim])
    :plan (:goal [modify ?component-property ?component])
    )

;;; modify a data-set by controlling a process that controls the data-set
(defattack-method modify-through-controller
    :to-achieve [modify ?victim-property ?victim]
    :bindings ([attacker-and-machine ?attacker ?attacker-machine])
    :typing ((?controller process)
             (?victim data-set))
    :prerequisites ([process-controls-data-set ?controller ?victim])
    :plan (:sequential
           (:goal [take-control-of (controlled-data-set ?victim) ?controller])
           (:goal [use-control-of-to-affect-resource ?attacker ?controller ?victim-property ?victim]))
    )

;;; NOTE: This should be expressed in a more general way about transforming formats
;;; but it will do for now.
(defattack-method modify-loadable-code
    :to-achieve [modify ?file-property ?object-file]
    :typing ((?object-file dynamically-loadable-code-file))
    :bindings ()
    :plan (:sequential
	   (:goal [modify code ?object-file.source-file])
	   (:goal [force-compilation ?attacker ?source-file ?object-file]))
    )

;;; The method compiler could be more clever about placement of bindings
;;; and typing.  Typing of stuff that's available before binding can be move up
;; in the if-part.

;;; Here ?user is again feedback to the caller about whose rights you got
;;; Is that different than ?foothold role ?
;;; Fix: Need two vesions.  IF ?foothold-role already has the access right
;;; then you do nothing.  Otherwise you go through achieve-access-right
;;; Partially fixed
(defattack-method modify-through-access-rights
    :to-achieve [modify ?object-property ?object]
    :bindings ([attacker-and-machine ?attacker ?attacker-computer]
	       [current-foothold ?current-foothold-computer ?current-foothold-role])
    :typing ((?object.machines computer))
    ;; Use this only if you don't already have the required capability
    ;; (what if more than one capability implies the right?  Shouldn't
    ;; we check that he doesn't have any of them).
    :plan (:sequential
           (:goal [achieve-access-right write ?object ?other-role])
	   (:goal [make-connection ?object.machines database-protocol])
	   (:action [use-access-right-to-modify ?attacker write ?other-role ?current-foothold-computer ?object ?object.machines])
           )
    )

;;; To increase the size of the active user set of some OS
;;; Find a user in the authorization pool for the OS
;;; and make that user a member of the active user set
(defattack-method modify-size-by-increase-size
    :to-achieve [modify size ?object]
    :plan (:goal [increase-size ?object])
    )

(defattack-method modify-active-user-set
    :to-achieve [increase-size ?active-user-set]
    :bindings ()
    :typing ((?active-user-set user-set)
             (?active-user-set.os.authorization-pool authorization-pool)
             (?active-user-set.os.authorization-pool.users user))
    :plan (:goal [make-member-of ?active-user-set.os.authorization-pool.users ?active-user-set])
    )



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Remote Execution
;;;
;;; Achieve-Remote-Execution is intimately bound up with get-foothold (i.e. lateral-motion)
;;; Get-foothold tries to find somebody that can made the desired connection
;;; and then tries to achieve remote execution of some kind on that machine
;;; But to achieve remote execution on that machine you need to get another foothold from
;;; which to launch the appropriate attack to get remote execution on the original foothold
;;;
;;; There are many ways of getting remote execution and so each of these will have a specific
;;; requirement for what protocol the new foothold machine will require to get to the target
;;; foothold i.e. if you're trying to get a remote shell then you'll need a foothold that can
;;; reach the target through either ssh or telnet.  If you're trying to take over a web server process
;;; then you'll need to find a machine that can speak http or https
;;; If there's some type of specific server with its own protocol then you'll need a foothold that
;;; can reach the machine via that specific protocol.
;;;
;;; Achieve-remote-execution takes two arguments:
;;;  1) The machine to get execution on, an input
;;;  2) The role under which you have remote execution, an output
;;;      Typically a user or a process
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


;;; Here ?victim-user can be passed in unbound and will be unified with whoever you log in as
;;; There might be a more general way to organize this where there's a predicate (e.g. protocol-for-remote-execution)
;;; and a bunch of rules that takes a remote execution type and return a protocol name that's relevant for it.
;;; The reason for the rule is for example, remote shell cold be either ssh or telnet and by making it a rule
;;; we can generate them.

(defattack-method remote-execution-to-remote-shell
    :to-achieve [achieve-remote-execution ?victim-machine ?victim-user]
    :outputs (?victim-user)
    :guards ([not [place-already-visited? ?victim-machine remote-execution]])
    :bindings ((?victim-user ?victim-machine.os.users))
    :typing ((?victim-machine.os operating-system)
             (?victim-machine.os.users user)
	     (?victim-machine computer))
    :plan (:sequential
	   (:note [place-visited ?victim-machine remote-execution])
	   (:goal [achieve-remote-shell ?victim-machine.os ?victim-user])
           )
    )

;;; Note: This is odd if the way you get knowledge of the password
;;; is by phishing or something else that takes time
;;; In such cases, the first get-foothold here establishes a connection
;;; But then the achieve-knowledge-of-password does a bunch of other actions
;;; before the connection is used.
;;; Better would be for the get-foothold not to be here
;;; but within two different versions of login, one for when you
;;; already have the foothold (as you would in achieving-knowledge by password
;;; guessing and one for when you don't.  The second case would do the get-foothold.

;;; Note that ?victim-user is an input variable at this point
;;; It's bound by the method right above.
;;; Note: If victim-computer isn't bound in a value-of, the compiler
;;; screws up, see *cl-temp* buffer
(defattack-method how-to-logon
    :to-achieve [achieve-remote-shell ?victim-os-instance ?victim-user]
    :outputs ()
    :bindings (;; I think this isn't right.  We're posting a get-foothold goal
	       ;; below, which means that the foothold from which the login
	       ;; will happen is that foothold not the current one (they might be
	       ;; the same in some cases);
               ;; [current-foothold ?current-foothold-machine ?current-foothold-role]
               (?victim-computer ?victim-os-instance.machine)
	       [attacker-and-machine ?attacker ?attacker-machine]
	       [protocol-for remote-execution remote-shell ?protocol])
    :typing ((?victim-os-instance operating-system)
	     (?victim-computer computer)
	     (?victim-user user))
    :plan (:sequential
	   (:goal [get-foothold ?victim-computer ?protocol])
	   (:goal [achieve-knowledge-of-password ?attacker ?victim-user ?victim-computer])
           (:action [login ?victim-user ?victim-os-instance ?current-foothold-machine ?current-foothold-role]))
    :post-conditions ([has-remote-execution ?attacker ?victim-computer ?victim-user])
    )

#|

Test case for how the early-typing hack works in the method compiler

(defattack-method how-to-logon-test
    :to-achieve [achieve-remote-shell ?victim-os-instance ?victim-user]
    :outputs (?victim-user)
    :bindings (;; I think this isn't right.  We're posting a get-foothold goal
	       ;; below, which means that the foothold from which the login
	       ;; will happen is that foothold not the current one (they might be
	       ;; the same in some cases);
               ;; [current-foothold ?current-foothold-machine ?current-foothold-role]
	       [attacker-and-machine ?attacker ?attacker-machine]
	       [protocol-for remote-execution remote-shell ?protocol])
    :typing ((?victim-os-instance operating-system)
	     (?victim-os-instance.machine computer)
	     (?victim-user user))
    :plan (:sequential
	   (:goal [get-foothold ?victim-os-instance.machine ?protocol])
	   (:goal [achieve-knowledge-of-password ?attacker ?victim-user ?victim-os-instance.machine])
           (:action [login ?victim-user ?victim-os-instance ?current-foothold-machine ?current-foothold-role]))
    :post-conditions ([has-remote-execution ?attacker ?victim-computer ?victim-user])
    )

|#

;;; The stuff with noting place visited is there to prevet goal reduction loops
;;; We note that we've already tried to achieve execution on this machine and this
;;; produces a new context which is the context for achieving the goal

;;; Note that ?victim-process is an output and isn't bound at this point!
(defattack-method remote-execution-to-code-injection
    :to-achieve [achieve-remote-execution ?victim-machine ?victim-process]
    :guards ([not [place-already-visited? ?victim-machine remote-execution]])
    :bindings ((?victim-process ?victim-machine.os.processes))
    :typing ((?victim-machine.os operating-system)
             (?victim-machine computer)
	     (?victim-machine.os.processes process))
    :prerequisites ()
    :plan (:sequential
	   (:note [place-visited ?victim-machine remote-execution])
	   (:goal [achieve-code-injection ?victim-process ?victim-machine.os])))

;;; Note that ?process is bound by the method above and is an input.
(defattack-method code-injection-against-process
    :to-achieve [achieve-code-injection ?process ?os-instance]
    :bindings ([attacker-and-machine ?attacker ?attacker-machine])
    :typing ((?process web-server-process))
    :prerequisites ([bind ?process.host-os ?os-instance]
                    [is-vulnerable-to ?process buffer-overflow-attack ?protocol])
    :plan (:sequential
	   (:goal [get-foothold ?process.machines ?protocol])
	   (:action [launch-code-injection-attack ?attacker ?process ?protocol ?foothold-machine ?foothold-role]))
    :post-conditions ([has-remote-execution ?attacker ?process.machines ?process])
    )

;;; Note that ?victim-process is an output and isn't bound at this point!
(defattack-method remote-execution-to-code-reuse
    :to-achieve [achieve-remote-execution ?victim-machine ?victim-process]
    :outputs (?victim-process)
    :guards ([not [place-already-visited? ?victim-machine remote-execution]])
    :bindings ((?victim-process ?victim-machine.os.processes))
    :prerequisites ([value-of ?victim-process.host-os ?victim-machine.os])
    :typing ((?victim-machine.os operating-system)
	     (?victim-process process))
    :plan (:sequential
	   (:note [place-visited ?victim-machine remote-execution])
	   (:goal [achieve-code-reuse ?victim-process ?victim-machine.os])))

;;; Note that ?process is an input and is bound at this point
(defattack-method code-reuse-against-web-server
    :to-achieve [achieve-code-reuse ?process ?os-instance]
    :bindings ((?victim-machine ?process.machines)
	       [attacker-and-machine ?attacker ?attacker-machine])
    :typing ((?process web-server-process)
             (?process.host-os operating-system))
    :prerequisites ([is-vulnerable-to ?process buffer-overflow-attack ?protocol]
                    [value-of ?process.host-os ?os-instance])
    :plan (:sequential
	   (:goal [get-foothold ?victim-machine ?protocol])
	   (:action [launch-code-reuse-attack ?attacker ?process  ?protocol ?foothold-machine ?foothold-role])))

;;; Note that ?victim-user is an output and isn't bound on entry
(defattack-method remote-execution-to-corrupt-attachment
    :to-achieve [achieve-remote-execution ?victim-machine ?victim-user]
    :outputs (?victim-user)
    :guards ([not [place-already-visited? ?victim-machine remote-execution]])
    :bindings ((?victim-user ?victim-machine.os.users)
               [attacker-and-machine ?attacker ?attacker-machine])
    :typing ((?victim-user user)
             (?process process))
    :prerequisites ([email-client-of ?victim-user ?process])
    :Plan (:sequential
           (:note [place-visited ?victim-machine remote-execution])
           (:goal [get-user-to-click-on ?attacker ?victim-user ?clicked-on-thing ?new-process])))

;;; This includes implicitly the action of launching the process
;;; that's appropriate for the attachment
;;; Note that ?victim-user is an input and is bound at this point
(defattack-method remote-execution-via-corrupt-email
    :to-achieve [get-user-to-click-on ?attacker ?victim-user ?attachment ?new-process]
    :bindings ([email-client-of ?victim-user ?email-process]
               (?victim-computer ?victim-user.machines)
               (?victim-os ?victim-computer.os)
	       (?email-server-machine ?email-process.host-os.machine)
	       [attacker-and-machine ?attacker-machine ?attacker]
	       )
    ;; Note that the typing for normal-user implies that
    ;; you can't throw this at a sysadmin
    :typing ((?victim-user normal-user)
	     (?victim-os operating-system)
             (?victim-computer computer)
	     (?email-process email-server-process)
             (?email-server-machine computer)
	     (?attacker-machine computer))
    :plan (:sequential
           (:action [create-email-with-corrupt-attachment ?attacker office ?email-message ?attachment])
           (:goal [get-foothold ?email-server-machine smtp])
	   (:bind [current-foothold ?foothold-machine ?foothold-role])
	   (:action [send-email ?attacker ?email-message ?foothold-machine ?email-server-machine ?victim-user])
	   (:action [user-clicks-on-attachment ?victim-user ?victim-computer ?email-message ?attachment ?new-process])
           (:action [system-launches-process-for-file ?victim-os ?victim-computer ?victim-user ?attachment ?new-process])
           )           
    :post-conditions ([current-foothold ?victim-computer ?new-process]
                      [has-remote-execution ?attacker ?victim-computer ?new-process])
    )

;;; note for compiler: Might want to have a :typing form in the plan so that when an action returns an output
;;; we could type check it.  But hopefully the action has done that so no need to here.


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Performance related specifics
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; If somebody has goined direct control of the job-launcher
;;; They can affect performance by adding jobs
(defattack-method add-jobs-after-job-launcher-is-hacked
    :to-achieve [use-control-of-to-affect-resource ?attacker ?controller performance ?target]
    :bindings ((?controller ?os.job-admitter)
               (?input ?os-instance.workload))
    :typing ((?controller os-job-admitter)
             (?os operating-system)
             (?input os-workload)
	     (?target process))
    :plan (:action [add-user-jobs ?attacker ?input])
    )


(defattack-method modify-job-request-queue
    :to-achieve [increase-size ?user-job-launch-queue]
    :bindings ([attacker-and-machine ?attacker ?attacker-machine])
    :typing ((?user-job-launch-queue job-launch-request-queue)
             (?user-job-launch-queue.os.machine computer)
	     (?attacker-machine computer))
    :plan (:sequential
           (:goal [achieve-remote-execution ?user-job-launch-queue.os.machine ?entity])
           (:repeated-action [submit-user-jobs ?entity ?user-job-launch-queue])))

;;; If you control a process that produces an output
;;; you can use that control to mung the data-structure in core
(defattack-method mung-in-core-data-structures
    :to-achieve [use-control-of-to-affect-resource ?attacker ?process data-integrity ?data-set]
    :bindings ([output-of ?process ?data-set]
	       [current-foothold ?foothold-machine ?foothold-role])
    :typing ((?process process))
    :Prerequisites ([has-control-of ?attacker ?property ?process])
    :plan (:action [modify-data-structures ?process ?data-set ?foothold-machine ?foothold-role])
    )


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Methods for hacking access rights and gaining access
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defattack-method how-to-read-a-resource
    :to-achieve [achieve-knowledge-of-contents ?resource]
    :bindings ([value-of ?resource.authorization-pool ?victim-pool]
               [value-of ?victim-pool.users ?victim-user]
               [value-of ?victim-user.machines ?victim-machine]
               [attacker-and-machine ?attacker ?attacker-machine])
    :prerequisites ([value-of (?victim-user typical-p) t])
    :typing ((?resource data-resource))
    :plan (:sequential
	   (:goal [achieve-remote-execution ?victim-machine ?victim-user])
           (:goal [achieve-access-right read ?resource ?privileged-user])
           (:action [read-with-rights-of ?attacker ?privileged-user ?resource])
	   (:action [open-ftp-connection ?attacker ?victim-machine ?attacker-machine])
	   (:action [trasmit-data ?attacker ?resource ?victim-machine ?attacker-machine])
	   ))

;;; If your foothold role already has the access rights
;;; do nothing
(defattack-method achieve-a-right-you-already-have
    :to-achieve [achieve-access-right ?right ?object ?foothold-role]
    :bindings ([current-foothold ?foothold-machine ?foothold-role])
    :guards ([has-permission ?foothold-role ?right ?object])
    :plan (:action [goal-already-satisfied [achieve-access-right ?right ?object ?foothold-role]])
    )

(defattack-method achieve-a-right-you-dont-have
    :to-achieve [achieve-access-right ?right ?object ?other-user]
    :outputs (?other-user)
    :bindings ([current-foothold ?foothold-machine ?foothold-role]
	       [attacker-and-machine ?attacker ?attacker-machine]
	       [has-permission ?other-user ?right ?object])
    :guards ([not [has-permission ?foothold-role ?right ?object]])
    :plan (:goal [achieve-knowledge-of-password ?attacker ?other-user ?foothold-machine]))

(defattack-method achieve-domain-admin-rights
    :to-achieve [achieve-access-right ?right ?object ?domain-administrator]
    :bindings ([current-foothold ?foothold-machine ?foothold-role]
	       [attacker-and-machine ?attacker ?attacker-machine]
               [has-remote-execution ?attacker ?victim-computer ?victim-role]
               (?victim-os ?victim-computer.os)
               (?domain ?object.authorization-pool)
               [requires-access-right ?object ?right ?domain-admin]
               [system-role ?domain domain-administrator ?domain-administrator]
               )
    :prerequisites ([value-of (?domain-admin role) domain-admin-capability])
    :typing ((?object computer-resource)
             (?domain domain)
             (?sysvol directory)
             )
    :guards ([not [has-permission ?foothold-role ?right ?object]])
    :plan (:sequential
           (:action [scan ?attacker ?sysvol domain-admin-password ?password])
           (:action [scan ?attacker ?sysvol domain-admin-password-key ?key])
           (:action [decrypt ?attacker ?password ?key ?decrypted-password])
           (:action [launch-process ?attacker ?victim-computer ?victim-os shell ?domain-administrator ?victim-role])
           )
    )

;;; The ?user part of this is actually to feed back to the higher
;;; level that it should read the file with the access rights of the user
;;; but is that really necessary, why isn't the process enough

;;; Note that this approach would normally be used from a remote foothold
;;; That can reach whatever process you want, and such that this process can
;;; then make a contact to the victim object.
;;; So the strategy would be to identify a process that runs on a machine that can reach the target
;;; and that has the accesss rights you need.
;;; Then figure out how to get to a foothold that can reach the process's machine
;;; then do this.

(defattack-method achieve-access-right-by-user-process-subversion
    :to-achieve [achieve-access-right ?right ?object ?user]
    :outputs (?user)
    ;; all this is asking is there a process in the workload
    ;; and if so with which user's permissions is it running
    :bindings ([value-of ?object.machines ?machine]
               [value-of ?machine.os ?os-instance]
               [value-of ?os-instance.workload ?os-workload]
               [value-of ?os-workload.user-workload.processes ?the-process]
               [runs-with-permissions-of ?the-process ?user]
	       [attacker-and-machine ?attacker ?attacker-machine]
	       [current-foothold ?foothold-machine ?foothold-role]
               )
    :typing ((?object computer-resource)
             (?machine computer)
             (?os-instance operating-system)
             (?os-workload os-workload)
             (?the-process process)
             )
    ;; This is the key pre-req: The process has the desired right to the object
    :prerequisites ([has-permission ?the-process ?right ?object])
    :plan (:sequential
	   (:goal [takes-direct-control-of ?attacker execution ?the-process]))
    )

(defattack-method achieve-access-right-by-server-process-subversion
    :to-achieve [achieve-access-right ?right ?object ?user]
    :outputs (?user)
    ;; all this is asking is there a process in the workload
    ;; and if so with which user's permissions is it running
    :bindings ((?the-process ?object.machines.os.workload.server-workload.processes)
               [runs-with-permissions-of ?the-process ?user]
	       [attacker-and-machine ?attacker ?attacker-machine]
	       [current-foothold ?foothold-machine ?foothold-role]
               )
    :typing ((?object computer-resource)
             (?the-process process)
             )
    ;; This is the key pre-req: The process has the desired right to the object
    :prerequisites ([has-permission ?the-process ?right ?object])
    :plan (:sequential
	   (:goal [takes-direct-control-of ?attacker execution ?the-process]))
    )

;;; similar comment to above about foothold etc
;;; ?other-user is an output variable that isn't bound at this point
(defattack-method how-to-achieve-access-right-by-remote-shell-on-target
    :to-achieve [achieve-access-right ?right ?object ?other-user]
    :outputs (?other-user)
    :bindings ([value-of ?object.machines ?machine]
               [value-of ?machine.os ?os-instance]
               [requires-access-right ?object ?right ?capability]
	       [value-of ?os-instance.authorization-pool ?pool]
	       [value-of ?pool.users ?other-user]
	       [current-foothold ?foothold-machine ?foothold-role]
	       [value-of ?foothold-machine.os ?foothold-os])
    :typing ((?object computer-resource)
             (?machine computer)
             (?os-instance operating-system)
	     (?pool authorization-pool)
             (?other-user user))
    ;; Note: has-capability is a function not an assertion
    :prerequisites ((has-capability ?other-user ?capability))
    :plan (:sequential
           (:Goal [achieve-remote-shell ?foothold-os ?other-user]))
    )



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Active User Set and Logging in
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defattack-method join-active-user-set
    :to-achieve [make-member-of ?user ?active-user-set]
    :bindings ((?os-instance ?active-user-set.os))
    :typing ((?active-user-set user-set)
             (?os-instance operating-system))
    :plan (:goal [achieve-remote-shell ?os-instance ?user])
    )



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Passwords and secrets
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defattack-method user-knows-own-password
    :to-achieve [achieve-knowledge-of-password ?attacker ?user ?victim-machine]
    :guards ([unifiable ?attacker ?user])
    :plan (:action [use-own-password ?user ?victim-machine])
    )

(defattack-method how-to-get-password-by-guessing
    :to-achieve [achieve-knowledge-of-password ?attacker ?user ?victim-machine]
    :guards ([is-typical-user ?user]
	     [not [unifiable ?attacker ?user]])
    :plan (:action [guess-password ?attacker ?user ?victim-machine])
    )

(defattack-method guess-superuser-passwords
    :to-achieve [achieve-knowledge-of-password ?attacker ?user ?victim-machine]
    :bindings ([value-of ?user.machines ?machine]
	       [value-of ?machine.os.superuser  ?user])
    :guards ([not [unifiable ?attacker ?user]])
    :typing ((?user user)
	     (?machine computer))
    :plan (:action [guess-password ?attacker ?user ?victim-machine])
    )

(defattack-method get-sysadmin-password-by-bricking
    :to-achieve [achieve-knowledge-of-password ?attacker ?victim-user ?victim-machine]
    :bindings ([value-of ?victim-user.machines ?victim-machine]
	       [value-of ?victim-machine.os.superuser ?victim-user]
	       [current-foothold ?foothold-machine ?foothold-role])
    :typing ((?victim-user user)
	     (?victim-machine computer))
    :prerequisites ()
    :plan (:sequential
	   (:goal [install-malware ?attacker ?victim-machine key-logger])
	   (:goal [brick-machine ?attacker ?victim-machine])
	   (:action [capture-password-through-keylogger ?attacker ?victim-user ?victim-machine])
	   ))

(defattack-method brick-machine-by-kill-disk
    :to-achieve [brick-machine ?attacker ?victim-machine]
    :bindings ()
    :prerequisites ([has-remote-execution ?attacker ?victim-machine ?role])
    :plan (:sequential
	   (:goal [install-malware ?attacker ?victim-machine kill-disk])
	   (:action [fill-disk ?attacker ?victim-machine kill-disk])
	   ))

(defattack-method download-and-load-malware
    :to-achieve [install-malware ?attacker ?victim-machine ?malware-package]
    :bindings ([attacker-download-server ?attacker ?download-server])
    :typing ()
    :prerequisites ([has-remote-execution ?attacker ?victim-machine ?foothold-role])
    :plan (:sequential
	   (:action [connect-via ?victim-machine ?foothold-role ?download-server ftp])
	   (:action [download-software ?malware-package ?download-server ?victim-machine ?foothold-role])
	   (:action [load-software ?malware-package ?victim-machine]))
    :Post-conditions ([malware-installed-on-machine ?attacker ?victim-machine ?malware-package])
    )

;;; This is a stub
; (defattack-method how-to-install-malware
;     :to-achieve [install-malware ?attacker ?victim-machine ?malware-type]
;     :prerequisites ()
;     :plan (:action [install-malware ?attacker ?malware-type ?victim-machine]))


;note: need plan for install malware

;;; Fix This:
;;; To pull off a phishing attack:
;;;  The attacker must have a foothold for the email server of the victim-user
;;;
(defattack-method how-to-get-password-by-phishing
    :to-achieve [achieve-knowledge-of-password ?attacker ?victim-user ?victim-machine]
    :bindings ([email-client-of ?victim-user ?process]
	       [attacker-and-machine ?attacker ?attacker-machine]
	       [value-of ?process.host-os ?os-instance]
	       [value-of ?os-instance.machine ?email-server-machine]
	       [attacker-download-server ?attacker ?attacker-server]
	       )
    :typing ((?victim-user user)
	     (?process email-server-process)
	     (?os-instance operating-system)
             (?email-server-machine computer)
	     (?attacker-machine computer))
    :plan (:sequential
	   (:goal [get-foothold ?email-server-machine smtp])
	   (:bind [current-foothold ?foothold-machine ?foothold-role])
	   (:action [send-phishing-email ?attacker ?foothold-machine ?email-server-machine ?victim-user ?process])
	   (:action [connect-via ?victim-machine ?victim-user ?attacker-server http])
	   )
    :post-conditions ([current-foothold ?current-foothold-machine ?current-foothold-role]
		      [knows-credentials ?attacker ?victim-user]
		      )
    )


(defattack-method how-to-get-password-by-sniffing
    :to-achieve [achieve-knowledge-of-password ?attacker ?user ?victim-machine]
    :typing ((?user user)
             (?victim-machine computer)
             (?subnet subnet))
    :bindings ((?subnet ?victim-machine.subnets))
    :plan (:parallel
           (:goal [observe-network-traffic ?attacker ?subnet])
           (:action [sniff-a-password ?attacker ?user ?subnet]))
    )

;;; to be filled in: you can get his password by external sniffing of unsecured protocols
;;; such as smtp, pop

;;; ((:goal (connect ?machine) :plan ((:action (connect-via ?protocol-name ?machine)))))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Lateral Motion
;;; If the attacker is trying to achieve a connection to a target machine "A" using some specific protocol
;;; There are two cases:
;;; 1) The attacker can reach A from its current position
;;; 2) The attacker can't reach A using that protocol from its current position.
;;;    In this case the attacker follows this strategy
;;;    a) Find a machine B that can make the intended connection
;;;    b) Get some form of remote execution on B
;;;    c) Have B make the connection to A
;;;    Achieving remote execution on B, however, may not be directly achievable
;;;    Because that requires connecting to B from the attacker's position using
;;;    whatever protocol is relevant for the exploit that allow remote execution
;;;    So the operator that achieves remote execution on B may need to get a foothold
;;;    on some machine C that can reach B, and so on recursively.
;;;
;;;    One thing that complicates this reasoning is that when B isn't directly reachable and the attacker tries
;;;    to find a foothold to B (which was the foothold to get to A), we might discover that A could serve as the foothold
;;;    to B.  But then we'd be in an infinite goal descent.
;;; So to prevent this we do something hokey:
;;; 1) We put a guard on the operator, saying that it's only valid if it hasn't already been visited
;;; 2) We add a "note" in the plan saying that we should note that we've visited this place
;;;
;;; Corresponding to the two cases there are two methods
;;; There are two attack-methods:
;;; From the easy case (1):  Direct-Foothold
;;; For the hard caser (2): Lateral-motion
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


;;; Direct Method, applicable when you can get from your current foothold to the target-machine
;;; so the foothold is where this step is taking place from and the role is the attacker
(defattack-method direct-foothold
    :to-achieve [get-foothold ?victim-machine ?protocol-name]
    :guards ([not [place-already-visited? ?victim-machine foothold]])
    :bindings ((?victim-os ?victim-machine.os)
	       [current-foothold ?current-foothold-machine ?current-foothold-role]
	       )
    :typing ((?victim-os operating-system)
	     (?victim-machine computer)
	     (?current-foothold-machine computer))
    :prerequisites ([accepts-connection ?victim-machine ?protocol-name ?current-foothold-machine])
    :plan (:action [connect-via ?current-foothold-machine ?current-foothold-role ?victim-machine ?protocol-name])
    :post-conditions ([has-foothold ?victim-machine ?current-foothold-machine ?current-foothold-role ?protocol-name])
    )

(defattack-method lateral-motion
    :to-achieve [get-foothold ?victim-machine ?protocol-name]
    :bindings ((?victim-os ?victim-machine.os)
	       ;; Now find somebody that can make the connection, accepts connection will find one if there is one
	       [current-foothold ?current-foothold-machine ?current-foothold-role])
    :guards ([not [place-already-visited? ?victim-machine foothold]]
	     [foothold-doesnt-exist ?victim-machine]
	     ;; Use this method only if you can't get a connection to the victim from where you are
	     [not [accepts-connection ?victim-machine ?protocol-name ?current-foothold-machine]])
    :typing ((?victim-os operating-system)
	     (?victim-machine computer)
	     (?current-foothold-machine computer))
    :plan (:sequential
	   ;; Make a note that we've already considered this place as a foothold to
	   ;; prevent looping back to here while trying to achieve remote execution
	   (:note [place-visited ?victim-machine foothold])
	   ;; Now see if the attacker can gain remote execution on the new-foothold-machine and in what role
           ;; (?new-foothold-role is a return value)
           (:bind [accepts-connection ?victim-machine ?protocol-name ?new-foothold-machine])
	   (:goal [achieve-remote-execution ?new-foothold-machine ?new-foothold-role])
	   ;;If so then actually make the connection to the victim from the new foothold
	   ;; (:goal [make-connection ?victim-os-instance ?protocol-name ?remote-execution-state ?output-contet])
	   )
    :post-conditions ([has-foothold ?victim-machine ?new-foothold-machine ?new-foothold-role ?protocol-name]))




;;; to be filled in:
;;; if a remote request for a service arrives
;;; and the machine runs that service
;;; and the server admittance policy allows it
;;; then an instance of that server process is created
;;; this instance is part of the server workload
;;; it runs with the permissions of that server process type.

;;; if a user is logged in
;;; and the user requests a job to be started
;;; and if the user job admitter allows it
;;; then an instance of a user process is started
;;; it runs with the permission of the user


;;; These next several sections really are just knowledge rules
;;; not rules about attacking


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Network Traffic
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defattack-method control-the-network-stack
    :to-achieve [takes-direct-control-of ?attacker ?stack-property ?network-stack]
    :bindings ([value-of ?network-stack.host-os ?os-instance]
	       [value-of ?os-instance.network-monitor ?network-stack]
               [value-of ?os-instance.superuser ?superuser]
	       [attacker-and-machine ?attacker ?attacker-machine])
    :typing ((?network-stack network-stack)
             (?os-instance operating-system)
	     (?attacker-machine computer)
             (?superuser user))
    :plan (:sequential
           (:goal [achieve-remote-shell ?os-instance ?superuser])
           (:action [control ?attacker ?network-stack ?attacker-machine]))
    )

(defattack-method read-network-traffic
    :to-achieve [observe-network-traffic ?attacker ?subnet]
    :bindings ([value-of ?subnet.switch ?switch]
               [value-of ?switch.os ?os]
               [value-of ?os.network-monitor ?network-stack])
    :typing ((?subnet switched-subnet)
             (?switch switch)
             (?network-stack network-stack))
    :plan (:sequential
	   (:goal [takes-direct-control-of ?attacker network-traffic ?network-stack ])
	   (:action [observe ?attacker network-traffic ?subnet]))
    )



#|

Notes:

There are several cases where you want to get knowledge of something (e.g. a password)
and then use it later.  This can be dealt with either by careful
modularization which might be far too tricky, or by having a general
model that only runs rules on achieve-knowledge-of if there is no
predicate promising the thing is known.




|#

; Idea picked up at MRC PI Mtg
; Attacker let's lose a shit-storm with low value but high response cost
; Then uses the opportunity created by the diversion of attention to
; launch a high-value but perhaps more risky attack.
;;;
;;; Knowledge of memory contents as pre-requisite to overwriting attacks
;;; Memory disclosure attacks as way to gain knowledge of memory contents
;;;  Ability to read memory as pre-requisite to that
;;;    Privilege escalation as way to that
;;;    Buffer overread as read to do that
;;; Having copy of system as way to have knowledge of memory contents




;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Things relevant to control systems
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; If you want to affect the accuracy of a control process
;;; find it's sensors and then find a bus (or network) that
;;; those sensors are on and that the control process is also on
;;; the find another process that is also on that bus
;;; and send fake sensor data reports for that sensor to the control process


(defattack-method fake-sensor-data
    :to-achieve [affect accuracy ?controller-process]
    :bindings ((?controller-machine ?controller-process.machines)
	       ;; does that machine play the part of a controller in some control system
	       [system-role ?system controller ?controller-machine]
	       ;; if so find a sensor in that same system
	       [system-role ?system sensor ?sensor-machine]
	       ;; and a bus that both the sensor and the controller are on
	       [connected-to ?sensor-machine ? ?bus ?]
	       [connected-to ?controller-machine ? ?bus ?]
	       ;; now find a another (or the same) machine that's on that bus
	       [connected-to ?victim-machine ? ?bus ?]
	       ;; then find a process runnning on that machine
	       (?victim-os ?victim-machine.os)
	       )
    :prerequisites ([output-of ?sensor-machine ?signal]
		    ;; the output of the sensor must be an input to
		    ;; the controller process
		    [input-of ?controller-process ?signal]
		    [or [can-be-mastered-by ?controller-machine ?victim-machine ?bus]
			(equal ?controller-machine ?victim-machine)]
		    )
    :typing ((?controller-machine computer)
	     (?victim-machine computer)
	     (?controller-process control-system-process)
	     (?system system)
	     (?sensor-machine computer)
	     (?signal sensor-signal)
	     (?bus unmastered-medium)
	     (?victim-os operating-system)
	     )
    :plan (:sequential
	   ;; You have to specify what the entity here is
	   ;; it can either be a user or a process
	   ;; shouldn't really be in the operators that detemine how to do the remote execution
	   (:goal [achieve-remote-execution ?victim-machine ?entity])
	   ;; issue a false sensor data report to the controller from the attacker machine over the bus
	   ;; of the sensor type
	   (:action [issue-false-sensor-data-report ?controller-machine ?victim-machine ?bus ?signal]))
    )

; (defattack-method fake-command-data
;     :to-achieve [affect ?attacker accuracy ?controller-process]
;     :bindings ((?machine ?controller-process.machines)
; 	       [connected-to-bus ?machine ?interface ?bus ?slot]
; 	       [connected-to-bus ?other-machine ?other-interface ?bus ?other-slot]
; 	       (?os ?other-machine.os))
;     :prerequisites ((not (eql ?machine ?other-machine))
; 		    [can-be-mastered-by ?machine ?other-machine ?bus])
;     :typing ((?machine computer)
; 	     (?other-machine computer)
; 	     (?os operating-system)
; 	     (?bus bus))
;     :plan (:sequential
; 	   (:goal [remote-execution ?attacker ?entity ?os])
; 	   (:action [issue-incorrect-setpoint ?attacker ?machine ?other-machine ?bus]))
;     )

(defattack-method sensor-injection-attack
    :to-achieve [affect data-integrity ?signal]
    :bindings ((?machine ?signal.machines)
	       [attacker-and-machine ?attacker ?attacker-macine])
    :prerequisites ([system-role ?system sensor ?machine]
		    [is-proximate-to ?attacker ?victim radio])
    :typing ((?machine computer)
	     (?signal sensor-signal)
	     (?system system))
    :plan (:action [signal-noise-injection ?attacker ?machine ?signal])
    )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Quick hack for botnet recruitment ala Mirai
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defattack-method recruit-to-mirai-botnet
    :to-achieve [affect independence ?cycle-pool]
    :bindings ([attacker-and-machine ?attacker ?attacker-macine])
    :plan (:sequential
	   (:action [port-scan ?attacker ?cycle-pool.machines ?attacker-machine telnet-ports])
	   (:goal [get-foothold ?cycle-pool.machines telnet ?input-context ?foothold-context])
	   (:action [login ?attacker white-list-member ?cycle-pool.os ?foothold-machine])
	   (:action [download-malware-from-source ?attacker ?foothold-machine ?victim-machine mirai-client])))

#|

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Escaping the sandbox via Internet Explorer PIDL vulnerability
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


(defattack-method IE-pidl-vulnerability
    ;; The end goal of this attack is for the attacker to be able to execute malicious web-based code on the victim browser
    :to-achieve [achieve-remote-execution ?victim-machine ?victim-user]
    ;; Redundant to perform an attack on a machine that has already been infected
    :guards ([not [place-already-visited? ?victim-machine remote-execution]])
    ;; Probably need to implement a browser version binding because this attack is for IE only, 
    ;; the os is most likely always going to be Windows (not sure if I should specify the OS in this case)
    :bindings((?victim-os ?victim-machine.os)
	      (?victim-user ?victim-os.users))
    :typing ((?victim-machine computer)
             (?victim-user user)
             (?process browser-process)
             )
    ;; For this attack to work, the victim has to run a version of Internet Explorer including/earlier than IE 11
    :prerequisites(
		   [is-vulnerable-to ?process pidl-url-attack]
                   (break "Breaking in prerequisite after vulnerable")
		   ;;[user-click ?victim-user ?victim-machine ?object]
		   )
    ;; Check to see if machine has visited site before, break the sandbox, grasp the new foothold
    :plan (:sequential
	   (:break "In goals")
	   (:note [place-visited ?victim-machine remote-execution])
	   (:goal [break-browser-sandbox ?victim-machine ?victim-user ?process])
	   )
    ;; By the end of this attack, the attacker is able to execute arbitrary code on the victim machine and can peer into the local files
    :post-conditions ([has-remote-execution ?attacker ?victim-machine ?foothold-role]
		      [current-foothold ?current-foothold-machine ?current-foothold-role])
    )

|#