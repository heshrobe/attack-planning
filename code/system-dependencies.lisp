;;; -*- Syntax: Joshua; Package: APLAN; syntax: joshua; readtable: Joshua  -*-

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
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


(in-package :aplan)



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
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
    :to-achieve [affect ?desirable-property ?victim ?input-context ?output-context]
    ;; find some component of the OS of a machine that the victim runs on
    :bindings ([ltms:value-of (?victim machines) ?computer]
               [ltms:named-part-of ?computer os ?os-instance]
               [part-of ?os-instance ?component]
	       [current-foothold ?input-context ?foothold-machine ?foothold-role]
	       [attacker-and-machine ?input-context ?attacker ?attacker-machine])
    :typing ([ltms:object-type-of ?victim computer-resource]
             [ltms:object-type-of ?os-instance operating-system]
	     [ltms:object-type-of ?component process])
    :prerequisites ([impacts ?component-property ?component ?desirable-property ?victim])
    :plan (:sequential
           ;; this breaks down into two steps:
           ;; 1) Get control of some component of the victim
           ;; 2) Use that control to affect the property of the victim
           ;; Notice that the first step is oblivous to its purpose
           ;; This certainly makes things simpler but might lead to getting control in a way
           ;; that doesn't actually work
           (:goal [takes-control-of ?attacker ?component-property ?component ?input-context ?controlled-context])
           (:goal [use-control-of-to-affect-resource ?attacker ?component ?desirable-property ?victim ?controlled-context ?output-context]))
    )

(defattack-method affect-property-by-affecting-input
    :to-achieve [affect ?desirable-property ?victim ?input-context ?output-context]
    :prerequisites ([impacts ?resource-property ?resource ?desirable-property ?victim])
    :bindings ([attacker-and-machine ?input-context ?attacker ?attacker-machine])
    :typing ([ltms:object-type-of ?resource computer-resource])
    :plan (:goal [affect ?resource-property ?resource ?input-context ?output-context])
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
    :to-achieve [affect performance ?process ?input-context ?output-context]
    :prerequisites ([desirable-property-of ?process performance])
    :bindings ([ltms:value-of (?process host-os) ?os]
	       [ltms:value-of (?os machine) ?computer]
	       [ltms:value-of (?os workload) ?workload]
	       [protocol-is-relevant-for workload-size ?protocol]
	       [attacker-and-machine ?input-context ?attacker  ?attacker-machine])
    :typing ([ltms:object-type-of ?process process]
	     [ltms:object-type-of ?os operating-system]
	     [ltms:object-type-of ?workload os-workload])
    :plan (:sequential
	   (:goal [get-foothold ?computer ?protocol ?input-context ?foothold-context])
	   (:goal [increase-size ?workload ?foothold-context ?output-context]))
    )


(defattack-method send-lots-of-emails
    :to-achieve [affect performance ?process ?input-context ?output-context]
    :prerequisites ([desirable-property-of ?process performance])
    :bindings ([ltms:value-of (?process host-os) ?os-instance]
	       [ltms:value-of (?os machine) ?computer]
	       [current-foothold ?input-context ?foothold-machine ?foothold-role]
	       [attacker-and-machine ?input-context ?attacker ?attacker-machine])
    :typing ([ltms:object-type-of ?process email-server-process]
	     [ltms:object-type-of ?foothold-machine computer]
	     )
    :plan (:sequential
	   (:goal [get-foothold ?computer email ?input-context ?foothold-context])
	   (:repeated-action [submit-email ?attacker large-email ?process ?foothold-machine ?foothold-role]))
    :post-conditions ([current-foothold ?foothold-context ?foothold-machine ?foothold-role]
		      [unify ?foothold-context ?output-context])
    )

;;; now what we want to say is:
;;; Either 
;;; 1) find a process in the current workload that is capable of launching new jobs
;;; get control of that process and cause it launch jobs.  For example, a server that takes 
;;; requests through some protocol and launches jobs in response (e.g. web server ftp server)
;;; repeatedly connect to it and cause it to launch a job
;;; 2) Increase the size of the job launch queue

(defattack-method increase-workload-by-increasing-job-launch-queue
    :to-achieve [increase-size ?workload ?input-context ?output-context]
    :bindings ([ltms:value-of (?workload os) ?os]
	       [ltms:value-of (?os job-launch-queue) ?queue]
	       [ltms:named-part-of ?queue user-job-launch-request-queue ?user-job-launch-queue]
	       [current-foothold ?input-context ?foothold-machine ?foothold-role]
	       )
    :typing ([ltms:object-type-of ?workload os-workload]
	     [ltms:object-type-of ?os operating-system]
	     [ltms:object-type-of ?queue os-job-launch-request-queue]
	     [ltms:object-type-of ?user-job-launch-queue job-launch-request-queue])
    :plan (:goal [increase-size ?user-job-launch-queue ?input-context ?output-context]))



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Data Privacy
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defattack-method read-file-property-directly
    :to-achieve [affect data-privacy ?file ?input-context ?output-context]
    :prerequisites ([desirable-property-of ?file data-privacy])
    :typing ([ltms:object-type-of ?file data-resource])
    :plan (:goal [achieve-knowledge-of-contents ?file ?input-context ?output-context])
    )


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Data Integrity
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; Fix: Need to do an get-foothold to get foothold
(defattack-method write-file-property-directly
    :to-achieve [affect data-integrity ?file ?input-context ?output-context]
    :typing ([ltms:object-type-of ?file file])
    :prerequisites ([desirable-property-of ?file data-integrity])
    :plan (:goal [modify contents ?file ?input-context ?output-context])
    )

;;; To affect the data-integrity of some data-set
;;; Get control of a process that produces the data-set
(defattack-method mung-process-output
    :to-achieve [affect data-integrity ?data-set ?input-context ?output-context]
    :bindings ([output-of ?process ?data-set]
	       [attacker-and-machine ?input-context ?attacker ?attacker-machine])    
    :typing ([ltms:object-type-of ?process process])
    :plan (:sequential
           (:goal [takes-control-of ?attacker data-integrity ?process ?input-context ?controlled-context])
           (:goal [use-control-of-to-affect-resource ?attacker ?process data-integrity ?data-set ?controlled-context ?output-context]))
    )

(defattack-method mung-database
    :to-achieve [affect data-integrity ?database ?input-context ?output-context]
    :bindings ([ltms:value-of (?database capability-requirements) (write ?requirement)]
	       [ltms:value-of (?database machines) ?database-machine]
	       [ltms:named-part-of ?database-machine os ?database-os]
	       [current-foothold ?input-context ?current-foothold-machine ?current-foothold-role]
	       )
    :typing ([ltms:object-type-of ?database database]
	     [ltms:object-type-of ?current-foothold-role attacker]
	     [ltms:object-type-of ?database database]
	     [ltms:object-type-of ?database-os operating-system]
	     )
    :plan (:sequential
	   ;; Note that get-foothold treats the next-to-last two arguments as things that it binds.
	   ;; Also note that it might bind these to the same thine as the current foothold
	   ;; Also note that it returns in a state where you have remote-execution on the new-foothold-machine
	   ;; And you've opened a connecion to the victim machine
	   (:goal [get-foothold ?database-machine database-protocol ?input-context ?foothold-context])
	   (:goal [make-connection ?database-machine database-protocol ?foothold-context ?connected-context])
	   (:goal [modify data-integrity ?database ?connected-context ?output-context])
	   )
    )

(defattack-method actually-make-connection
    :to-achieve [make-connection ?victim-machine ?connection-type ?input-context ?output-context]
    :bindings ([current-foothold ?input-context ?current-foothold-machine ?current-foothold-role])
    :plan (:action [connect-via ?current-foothold-machine ?current-foothold-role ?victim-machine ?connection-type])
    :post-conditions ([unify ?input-context ?output-context])
    )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Direct Control
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defattack-method take-control-of-directly
    ;; Takes control of a component to ultimately affect some property of the target
    :to-achieve [takes-control-of ?attacker ?component-property ?component ?input-context ?output-context]
    :plan (:goal [takes-direct-control-of ?attacker ?component-property ?component ?input-context ?output-context]))

;;; one way to take direct control of a process is to
;;; first find some way to modify the loadable file so as to affect the property of the target
;;; and then cause the load of the loadable file of the program that's supposed to run in the process

;;; Fix modify
(defattack-method control-process-through-loadable-files
    :to-achieve [takes-direct-control-of ?attacker ?victim-property ?victim ?input-context ?output-context]
    :bindings ([ltms:value-of (?victim program) ?program]
               [ltms:value-of (?program load-files) ?file])
    :typing ([ltms:object-type-of ?victim process]
             [ltms:object-type-of ?program program]
             [ltms:object-type-of ?file dynamically-loadable-code-file])
    :plan (:sequential 
           (:goal [modify contents ?file ?input-context ?modified-context])
	   ;; Note: this is a hack right now.  Really it should be a goal which would involve
	   ;; a series of actions to cause the file to get loaded (logging in?, robooting?)
           (:action [load-file ?attacker ?file ?victim]))
    ;; Really the action should cause a change of context.
    ;; These post-conditions are standing in for that.
    :post-conditions ([unify ?modified-context ?loaded-context]
		      [unify ?loaded-context ?output-context])
    )

;;; Fixed:
;;; This mentions the host-os but it doesn't actually seem to carry through
;;; to the plan.  Just rationality check, I guess.
(defattack-method buffer-overflow-can-control-server-processes
    :to-achieve [takes-direct-control-of ?attacker ?process-property ?process ?input-context ?output-context]
    ;; :bindings ([ltms:value-of (?process host-os) ?os-instance])
    :typing ([ltms:object-type-of ?process process]
             ;; [ltms:object-type-of ?os-instance operating-system]
             )
    :prerequisites ((is-vulnerable-to ?process 'buffer-overflow-attack))
    :plan (:action [take-control-with-buffer-overflow ?attacker ?process])
    ;; The action here should cause a change of context
    ;; This simulates that for the moment
    :post-conditions ([unify ?input-context ?post-overflow-context]
		      [unify ?post-overflow-context ?output-context])
    )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Indirect Control
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defattack-method take-control-of-indirectly
    :to-achieve [takes-control-of ?attacker ?victim-property ?victim ?input-context ?output-context]
    :plan (:goal [takes-indirect-control-of ?attacker ?victim-property ?victim ?input-context ?output-context]))

;;; Find an input of the victim and modify its contents
;;; probably should say that the behavior is affected by the content
;;; Fix modify
(defattack-method control-component-through-input
    :to-achieve [takes-indirect-control-of ?attacker ?victim-property ?victim ?input-context ?output-context]
    ;; assumption is that we know thing
    :bindings ([input-of ?thing ?input])
    :plan (:goal [modify contents ?input ?input-context ?output-context])
    )


;;; want to say that if the property is affected by the size of the input
;;; then change the size of the input

;;; fix modify
(defattack-method control-component-through-input-size
    :to-achieve [takes-indirect-control-of ?attacker ?victim-property ?victim ?input-context ?output-context]
    ;; assumption is that we know thing
    :prerequisites ([impacts size ?input ?victim-property ?victim])
    :bindings ([input-of ?victim ?input])
    :plan (:goal [modify size ?input ?input-context ?output-context])
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
    :to-achieve [modify ?victim-property ?victim ?input-context ?output-context]
    :typing ()
    :bindings ([ltms:part-of ?victim ?component])
    :prerequisites ([impacts ?component-property ?component ?victim-property ?victim])
    :plan (:goal [modify ?component-property ?component ?input-context ?output-context])
    )

;;; modify a data-set by controlling a process that controls the data-set
(defattack-method modify-through-controller
    :to-achieve [modify ?victim-property ?victim ?input-context ?output-context]
    :bindings ([attacker-and-machine ?input-context ?attacker ?attacker-machine])
    :typing ([ltms:object-type-of ?controller process]
             [ltms:object-type-of ?victim data-set])
    :prerequisites ([process-controls-data-set ?controller ?victim])
    :plan (:sequential 
           (:goal [takes-control-of (controlled-data-set ?victim) ?controller ?input-context ?controlled-context])
           (:goal [use-control-of-to-affect-resource ?attacker ?controller ?victim-property ?victim ?controlled-context ?output-context])) 
    )

;;; NOTE: This should be expressed in a more general way about transforming formats
;;; but it will do for now.
(defattack-method modify-loadable-code
    :to-achieve [modify ?file-property ?object-file ?input-context ?output-context] 
    :prerequisites ([ltms:object-type-of ?object-file dynamically-loadable-code-file]
                    [ltms:value-of (?object-file source-file) ?source-file])
    :plan (:sequential (:goal [modify code ?source-file ?input-context ?modified-context])
                       (:goal [force-compilation ?attacker ?source-file ?object-file ?modified-context ?output-context]))
    )

;;; Here ?user is again feedback to the caller about whose rights you got
;;; Is that different than ?foothold role ?
;;; Fix: Need two vesions.  IF ?foothold-role already has the access right
;;; then you do nothing.  Otherwise you go through achieve-access-right
;;; Partially fixed
(defattack-method modify-through-available-access-rights
    :to-achieve [modify ?object-property ?object ?input-context ?output-context]
    :bindings ([ltms:value-of (?object machines) ?computer]
	       [current-foothold ?input-context ?current-foothold-machine ?current-foothold-role])
    :typing ([ltms:object-type-of ?computer computer])
    ;; Use this only if you don't already have the required capability
    ;; (what if more than one capability implies the right?  Shouldn't
    ;; we check that he doesn't have any of them).
    :prerequisites ((not (has-relevant-capability ?current-foothold-role 'write ?object)))
    :plan (:sequential 
	   (:goal [achieve-access-right write ?object ?user ?input-context ?have-rights-context])
	   (:action [use-access-right-to-modify write ?user ?object]))
    :post-conditions ([unify ?have-rights-context ?output-context])
    )

(defattack-method modify-through-available-access-rights-when-have-then
    :to-achieve [modify ?object-property ?object ?input-context ?output-context]
    :bindings ([ltms:value-of (?object machines) ?computer]
	       [current-foothold ?input-context ?current-foothold-machine ?current-foothold-role]
	       [attacker-and-machine ?input-context ?attacker ?attacker-machine])
    :typing ([ltms:object-type-of ?computer computer])
    ;; Use this only if you don't already have the required capability
    ;; (what if more than one capability implies the right?  Shouldn't
    ;; we check that he doesn't have any of them).
    :prerequisites ((has-relevant-capability ?current-foothold-role 'write ?object))
    :plan (:action [use-access-right-to-modify ?attacker write ?current-foothold-role ?object ?current-foothold-machine ?current-foothold-role])
    :post-conditions ([unify ?input-context ?output-context])
    )


;;; To increase the size of the active user set of some OS
;;; Find a user in the authorization pool for the OS
;;; and make that user a member of the active user set
(defattack-method modify-size-by-increase-size
    :to-achieve [modify size ?object ?input-context ?output-context]
    :plan (:goal [increase-size ?object ?input-context ?output-context])
    )

(defattack-method modify-active-user-set
    :to-achieve [increase-size ?active-user-set ?input-context ?output-context]
    :bindings ([ltms:value-of (?active-user-set os) ?os-instance]
               [ltms:value-of (?os-instance authorization-pool) ?authorization-pool]
               [ltms:value-of (?authorization-pool users) ?user])
    :typing ([ltms:object-type-of ?active-user-set user-set]
             [ltms:object-type-of ?os-instance operating-system]
             [ltms:object-type-of ?authorization-pool authorization-pool]
             [ltms:object-type-of ?user user])
    :plan (:goal [make-member-of ?user ?active-user-set ?input-context ?output-context])
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
;;; Foothold-role here is an output value that achieve-remote-execution is supposed to bind
;;; to either a user or a process
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


;;; Here foothold-role can be passed in unbound and will be unified with whoever you log in as
;;; There might be a more general way to organize this where there's a predicate (e.g. protocol-for-remote-execution)
;;; and a bunch of rules that takes a remote execution type and return a protocol name that's relevant for it.
;;; The reason for the rule is for example, remote shell cold be either ssh or telnet and by making it a rule
;;; we can generate them.

(defattack-method remote-execution-to-remote-shell
    :to-achieve [achieve-remote-execution ?victim-machine ?victim-user ?input-context ?output-context]
    :guards ([not [place-already-visited? ?input-context ?victim-machine remote-execution ?victim-user]])
    :bindings ([ltms:named-part-of ?victim-machine os ?victim-os]
	       [ltms:value-of (?victim-os users) ?victim-user]
	       [note-place-visited ?input-context ?victim-machine remote-execution ?victim-user ?visited-context]
	       )
    :typing ([ltms:object-type-of ?victim-os operating-system]
             [ltms:object-type-of ?victim-user user]
	     [ltms:object-type-of ?victim-machine computer])
    :prerequisites ()
    :plan (:goal [achieve-remote-shell ?victim-os ?victim-user ?visited-context ?output-context])
    :post-conditions ())

(defattack-method how-to-logon
    :to-achieve [achieve-remote-shell ?victim-os-instance ?victim-user ?input-context ?output-context]
    :bindings ([ltms:value-of (?victim-os-instance users) ?victim-user]
	       [ltms:value-of (?victim-os-instance authorization-pool) ?pool]
	       [ltms:value-of (?victim-os-instance machine) ?victim-machine]
	       [current-foothold ?input-context ?current-foothold-machine ?current-foothold-role]
	       [protocol-for remote-execution remote-shell ?protocol])
    :typing ([ltms:object-type-of ?victim-os-instance operating-system]
             [ltms:object-type-of ?pool authorization-pool]
	     [ltms:object-type-of ?victim-machine computer]
	     [ltms:object-type-of ?victim-user user])
    :plan (:sequential
	   (:goal [get-foothold ?victim-machine ?protocol ?input-context ?foothold-context])	   
           (:goal [achieve-knowledge-of-password ?current-foothold-role ?victim-user ?pool ?victim-machine ?foothold-context ?password-context])
           (:action [login ?victim-user ?victim-os-instance ?current-foothold-machine ?current-foothold-role]))
    :post-conditions ([current-foothold ?foothold-context ?next-foothold-machine ?next-foothold-role]
		      [has-foothold ?password-context ?victim-machine ?victim-user ?output-context]))

(defattack-method remote-execution-to-code-injection
    :to-achieve [achieve-remote-execution ?victim-machine ?victim-process ?input-context ?output-context]
    :guards ([not [place-already-visited? ?input-context ?victim-machine remote-execution ?victim-process]])
    :bindings ([ltms:named-part-of ?victim-machine os ?os-instance] 
	       [ltms:value-of (?os-instance processes) ?victim-process]
	       [note-place-visited ?input-context ?victim-machine remote-execution ?victim-process ?visited-context])
    :typing ([ltms:object-type-of ?os-instance operating-system]
	     [ltms:object-type-of ?victim-process process])
    :prerequisites ()
    :plan (:goal [achieve-code-injection ?victim-process ?os-instance ?visited-context ?output-context]))

(defattack-method code-injection-against-web-server
    :to-achieve [achieve-code-injection ?process ?os-instance ?input-context ?output-context]
    :bindings ([ltms:value-of (?os-instance processes) ?process]
	       [current-foothold ?input-context ?foothold-machine ?foothold-role])
    :typing ([ltms:object-type-of ?process web-server-process])
    :prerequisites ([vulnerable-to-overflow-attack ?process])
    :plan (:action [launch-code-injection-attack ?process ?foothold-machine ?foothold-role])
    :post-conditions ([unify ?input-context ?output-context])
    )

(defattack-method remote-execution-to-code-reuse
    :to-achieve [achieve-remote-execution ?victim-machine ?victim-process ?input-context ?output-context]
    :guards ([not [place-already-visited? ?input-context ?victim-machine remote-execution ?victim-process]])
    :bindings ([ltms:named-part-of ?victim-machine os ?os-instance]
	       [ltms:value-of (?os-instance processes) ?victim-process]
	       [note-place-visited ?input-context ?victim-machine remote-execution ?victim-process ?visited-context])
    :typing ([ltms:object-type-of ?os-instance operating-system]
	     [ltms:object-type-of ?victim-process process])
    :prerequisites ()
    :plan (:goal [achieve-code-reuse ?victim-process ?os-instance ?visited-context ?output-context]))

(defattack-method code-reuse-against-web-server
    :to-achieve [achieve-code-reuse ?process ?os-instance ?input-context ?output-context]
    :bindings ([current-foothold ?input-context ?foothold-machine ?foothold-role])
    :typing ([ltms:object-type-of ?process web-server-process])
    :prerequisites ([vulnerable-to-overflow-attack ?process])
    :plan (:action [launch-code-reuse-attack ?process ?foothold-machine ?foothold-role])
    :post-conditions ([unify ?input-context ?output-context]))

;;; Note: It's more general if we just say to achieve remote-execution
;;; and let the system determine whether that meant remote-shell, code-injection, code-reuse, etc.
;;; In deterimining how to do that it also determines what entity to do it as.

(defattack-method modify-job-request-queue
    :to-achieve [increase-size ?user-job-launch-queue ?input-context ?output-context]
    :bindings ([ltms:named-part-of ?full-job-launch-queue user-job-launch-request-queue ?user-job-launch-queue]
               [ltms:value-of (?full-job-launch-queue os) ?os-instance]
	       [ltms:value-of (?os-instance job-launch-queue) ?full-job-launch-queue]
	       [ltms:value-of (?attacker machines) ?attacker-machine]
	       )
    :typing ([ltms:object-type-of ?user-job-launch-queue job-launch-request-queue]
             [ltms:object-type-of ?full-job-launch-queue os-job-launch-request-queue]
             [ltms:object-type-of ?os-instance operating-system]
	     [ltms:object-type-of ?attacker-machine computer])
    :plan (:sequential
           (:goal [achieve-remote-execution ?os-instance ?entity ?input-context ?output-context])
           (:repeated-action [submit-user-jobs ?entity ?user-job-launch-queue])))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Performance related specifics
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; If somebody has goined direct control of the job-launcher
;;; They can affect performance by adding jobs
(defattack-method add-jobs-after-job-launcher-is-hacked
    :to-achieve [use-control-of-to-affect-resource ?attacker ?controller performance ?target ?input-context ?output-context]
    :bindings ([ltms:named-part-of ?os job-admitter ?controller]
               [ltms:value-of (?os-instance workload) ?input])
    :typing ([ltms:object-type-of ?controller os-job-admitter]
             [ltms:object-type-of ?os operating-system]
             [ltms:object-type-of ?input os-workload]
	     [ltms:object-type-of ?target process])
    :plan (:action [add-user-jobs ?attacker ?input])
    :post-conditions ([unify ?input-context ?output-context])
    )
    
;;; If you control a process that produces an output
;;; you can use that control to mung the data-structure in core
(defattack-method mung-in-core-data-structures
    :to-achieve [use-control-of-to-affect-resource ?attacker ?process data-integrity ?data-set ?input-context ?output-context]
    :bindings ([output-of ?process ?data-set]
	       [current-foothold ?input-context ?foothold-machine ?foothold-role])
    :typing ([ltms:object-type-of ?process process])
    :plan (:action [modify-in-core-data-structures ?process ?data-set ?foothold-machine ?foothold-role])
    :post-conditions ([unify ?input-context ?output-context]))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Methods for hacking access rights and gaining access
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; Eventually we need to treat actions as real things that change the state
(defattack-method how-to-read-a-file
    :to-achieve [achieve-knowledge-of-contents ?file ?input-context ?output-context]
    :bindings ([ltms:value-of (?file machines) ?machine]
	       [attacker-and-machine ?input-context ?attacker ?attacker-machine])
    :prerequisites ([achieve-remote-execution ?victim-machine ?user ?input-context ?execution-context])
    :typing ([ltms:object-type-of ?file file])
    :plan (:sequential
           (:goal [achieve-access-right ?user read ?file ?privileged-user ?input-context ?have-rights-context])
           (:action [read-with-rights-of ?attacker ?privileged-user ?file])
	   (:action [open-ftp-connection ?attacker ?attacker-machine])
	   (:action [trasmit-data ?attacker ?file ?attacker-machine])
	   )
    :post-conditions ([unify ?have-rights-context ?output-context])
    )

;;; If your foothold role already has the access rights
;;; do nothing
(defattack-method achieve-a-right-you-already-have 
    :to-achieve [achieve-access-right ?object ?right ?user ?input-context ?output-context]
    :bindings ([current-foothold ?input-context ?foothold-machine ?foothold-role])
    :prerequisites ([has-permission ?foothold-role ?object ?right])    
    :bindings ([unify ?user ?foothold-role])
    :plan ()
    :post-conditions ([unify ?input-context ?output-context])
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

(defattack-method achieve-access-right-by-process-subversion
    :to-achieve [achieve-access-right ?right ?object ?user ?input-context ?output-context]
    ;; all this is asking is there a process in the workload
    ;; and if so with which user's permissions is it running
    :bindings ([ltms:value-of (?object machines) ?machine]
               [ltms:named-part-of ?machine os ?os-instance]
               [ltms:value-of (?os-instance workload) ?os-workload]
               [or [ltms:value-of (?os-workload server-workload processes) ?the-process]
                   [ltms:value-of (?os-workload user-workload processes) ?the-process]]
               [runs-with-permissions-of ?the-process ?user]
	       [attacker-and-machine ?input-context ?attacker ?attacker-machine]
	       [current-foothold ?input-context ?foothold-machine ?foothold-role]
               )
    :typing ([ltms:object-type-of ?object computer-resource]
             [ltms:object-type-of ?machine computer]
             [ltms:object-type-of ?os-instance operating-system]
             [ltms:object-type-of ?os-workload os-workload]
             [ltms:object-type-of ?the-process process]           
             )
    ;; This is the key pre-req: The process has the desired right to the object
    :prerequisites ([has-permission ?the-process ?right ?object])
    :plan (:sequential
	   (:goal [takes-direct-control-of ?attacker execution ?the-process ?input-context ?controlled-context])
	   (:action [uses-control-to-achieve-access-right ?attacker ?right ?object ?foothold-machine]))
    :post-conditions ([unify ?controlled-context ?output-context])
    )

;;; similar comment to above about foothold etc
(defattack-method how-to-achieve-access-right-by-remote-shell-on-target
    :to-achieve [achieve-access-right ?right ?object ?other-user ?input-context ?output-context]
    :bindings ([ltms:value-of (?object machines) ?machine]
               [ltms:named-part-of ?machine os ?os-instance]
               [requires-access-right ?object ?right ?capability]
	       [ltms:value-of (?os-instance authorization-pool) ?pool]
	       [current-foothold ?input-context ?foothold-machine ?foothold-role]
	       [ltms:named-part-of ?foothold-machine os ?foothold-os]
	       [ltms:value-of (?pool users) ?other-user])
    :typing ([ltms:object-type-of ?object computer-resource]
             [ltms:object-type-of ?machine computer]
             [ltms:object-type-of ?os-instance operating-system]
	     [ltms:object-type-of ?pool authorization-pool]
             [ltms:object-type-of ?other-user user])
    ;; Note: has-capability is a function not an assertion
    :prerequisites ((has-capability ?other-user ?capability))
    :plan (:goal [achieve-remote-shell ?foothold-os ?other-user ?input-context ?output-context])
    )

;;;;;; Note & Fix: This calls itself recursively but has no protection against
;;;;;; ping-ponging
;;;(defattack-method how-to-achieve-access-right-by-remote-shell-indirectly
;;;    :to-achieve [achieve-access-right ?attacker ?right ?object ?user ?foothold-machine ?foothold-role]
;;;    :bindings ([ltms:value-of (?object machines) ?machine]
;;;               [ltms:named-part-of ?machine os ?os-instance]
;;;               [requires-access-right ?object ?right ?capability]
;;;	       [ltms:value-of (?os-instance authorization-pool) ?pool]
;;;	       [ltms:value-of (?pool users) ?user]
;;;	       ;; all this is about finding another machine in the enclave
;;;	       [ltms:value-of (?machine site) ?site]
;;;	       [ltms:value-of (?site enterprise) ?enterprise]
;;;	       [ltms:value-of (?enterprise sites) ?other-site]
;;;	       [ltms:value-of (?other-site subnets) ?other-subnet]
;;;	       [ltms:value-of (?other-subnet computers) ?other-machines]
;;;	       [ltms:named-part-of ?other-machine os ?other-os]
;;;	       )
;;;    :typing ([ltms:object-type-of ?object computer-resource]
;;;             [ltms:object-type-of ?machine computer]
;;;             [ltms:object-type-of ?os-instance operating-system]
;;;	     [ltms:object-type-of ?pool authorization-pool]
;;;             [ltms:object-type-of ?user user])
;;;    ;; Note: has-capability is a function not an assertion
;;;    :PREREQUISITES ((not (eql ?other-machines ?machine))
;;;		    [reachable-from ?machine ?other-machine ?]
;;;		    [reachable-from ?other-machine ?attacker ?]
;;;		    (has-capability ?user ?capability)
;;;		    (break "~a ~a ~a" ?user ?other-machine ?other-os))
;;;    :plan (:goal [achieve-remote-execution ?attacker ?user ?other-os ?foothold-machine ?foothold-role])
;;;    )




;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Active User Set and Logging in 
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defattack-method join-active-user-set
    :to-achieve [make-member-of ?user ?active-user-set ?input-context ?output-context]
    :bindings ([ltms:value-of (?active-user-set os) ?os-instance])
    :typing ([ltms:object-type-of ?active-user-set user-set]
             [ltms:object-type-of ?os-instance operating-system])
    :plan (:goal [achieve-remote-shell ?os-instance ?user ?input-context ?output-context])
    )



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Passwords and secrets
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defattack-method user-knows-own-password
    :to-achieve [achieve-knowledge-of-password ?attacker ?user ?pool ?victim-machine ?input-context ?output-context]
    :prerequisites ((prog1 t "have password ~a ~" ?attacker ?user)
		    (equal ?attacker ?user))
    :plan (:action [use-own-password ?user ?pool ?victim-machine])
    :post-conditions ([unify ?input-context ?output-context])
    )
            
(defattack-method how-to-get-password-by-guessing
    :to-achieve [achieve-knowledge-of-password ?attacker ?user ?pool ?victim-machine ?input-context ?output-context]
    :prerequisites ((prog1 t "guess password ~a ~" ?attacker ?user) 
		    (not (equal ?attacker ?user)))
    :plan (:goal [guess-password ?attacker ?user ?pool ?victim-machine ?input-context ?output-context ])
    :post-conditions ([unify ?input-context ?output-context])
    )

(defattack-method guess-typical-user
    :to-achieve [guess-password ?attacker ?user ?pool ?victim-machine ?input-context ?output-context]
    :typing ([ltms:object-type-of ?user user]
	     [ltms:value-of (?user typical-p) t]
             [ltms:object-type-of ?attacker attacker])
    :plan (:action [password-dictionary-lookup-attack ?attacker ?user ?victim-machine ?pool])
    :post-conditions ([unify ?input-context ?output-context])
    )

(defattack-method guess-superuser-passwords
    :to-achieve [guess-password ?attacker ?user ?pool ?victim-machine ?input-context ?output-context]
    :typing ([ltms:value-of (?user machines) ?machine]
             [ltms:value-of (?machine os superuser) ?user])
    :bindings ([ltms:object-type-of ?user user]
               [ltms:object-type-of ?machine computer])
    :plan (:action [password-dictionary-lookup-attack ?attacker ?user ?pool])
    :post-conditions ([unify ?input-context ?output-context])
    )

(defattack-method get-sysadmin-password-by-bricking
    :to-achieve [achieve-knowledge-of-password ?attacker ?victim-user ?resource ?victim-machine ?input-context ?output-context]
    :bindings ([ltms:value-of (?victim-user machines) ?victim-machine]
	       [current-foothold ?input-context ?foothold-machine ?foothold-role])
    :typing ([ltms:object-type-of ?victim-user user]
	     [ltms:object-type-of ?victim-machine computer])
    :prerequisites ([ltms:value-of (?victim-machine os superuser) ?victim-user])
    :plan (:sequential
	    (:goal [install-malware ?attacker ?victim-machine key-logger ?input-context ?post-malware-context])
	    (:goal [brick-machine ?attacker ?victim-machine ?post-malware-context ?output-context])
	    (:action [capture-password-through-keylogger ?attacker ?victim-user ?victim-machine])
	    ))

(defattack-method brick-machine-by-kill-disk
    :to-achieve [brick-machine ?attacker ?foothold-machine ?input-context ?output-context]
    :plan (:sequential
	   (:goal [install-malware ?attacker ?foothold-machine kill-disk ?input-context ?output-context])
	   (:action [fill-disk ?attacker ?foothold-machine kill-disk])
	   ))

;;; This is a stub
(defattack-method how-to-install-malware
    :to-achieve [install-malware ?attacker ?victim-machine ?malware-type ?input-context ?output-context]
    :prerequisites ()
    :plan (:sequential
	   (:action [install-malware ?attacker ?malware-type ?victim-machine]))
    :post-conditions ([unify ?input-context ?output-context]))


;note: need plan for install malware

;;; Fix This
(defattack-method how-to-get-password-by-phishing
    :to-achieve [achieve-knowledge-of-password ?attacker ?user ?resource ?victim-machine ?input-context ?output-context]
    :bindings ([email-client-of ?user ?process]
	       [ltms:value-of (?attacker machines) ?attacker-machine]
	       [ltms:value-of (?process host-os) ?os-instance]
	       [ltms:value-of (?os-instance machine) ?machine]
	       )
    :typing ([ltms:object-type-of ?user user]
	     [ltms:object-type-of ?process email-server-process]
	     [ltms:object-type-of ?os-instance operating-system]
             [ltms:object-type-of ?machine computer]
	     [ltms:object-type-of ?attacker-machine computer])
    :plan (:sequential
           (:goal [get-foothold ?attacker-machine smtp ?input-context ?output-context])
           (:action [phishing-attack ?attacker ?user ?process ?current-foothold-machine ?current-foothold-role]))
    :post-conditions ([current-foothold ?output-context ?current-foothold-machine ?current-foothold-role])
    )


; This stuff was in the thing above, but I'm not sure what it was trying to say

; ((:goal (know (password ?user)) 
; 	:plan ((:goal (sniff (password ?user))
; 		      :plan ((:goal (achieve-email-connection-to ?os-instance) 
; 				    :plan ?plan)
; 			     )))))

(defattack-method how-to-get-password-by-sniffing
    :to-achieve [achieve-knowledge-of-password ?attacker ?user ?resource ?victim-machine ?input-context ?output-context]
    :typing ([ltms:object-type-of ?user user]
             [ltms:object-type-of ?victim-machine computer]
             [ltms:object-type-of ?subnet subnet])
    :bindings ([ltms:value-of (?victim-machine subnets) ?subnet]
               )
    :plan (:parallel 
           (:goal [observe-network-traffic ?attacker ?subnet ?input-context ?output-context])
           (:action [sniff-a-password ?attacker ?user ?subnet]))
    )

 ; ((:goal (know (password ?user)) 
 ; 	 :plan (?observation-plan 
 ; 		(:action (sniff-a-passward ?user ?subnet)))))

;;; to be filled in: you can get his password by external sniffing of unsecured protocols
;;; such as smtp, pop

;;; ((:goal (connect ?machine) :plan ((:action (connect-via ?protocol-name ?machine)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Connecting
;;; get-foothold is given the following "In Arguments"
;;;  The attacker
;;;  Where  the attacker is starting from
;;;  The victim os instance
;;;  and what protocol he's trying
;;;  the 
;;; There is an "Out Argument" which is the first machine on the path from here
;;; and this machine is guaranteed to be directly reachable by the attacker
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


;;; Lateral MotionAchieve
;;; If you're trying to achieve a connection to a machine
;;; One way to do so is to find a different machine in the same enterprise
;;; Gain remote-execution on that machine and then
;;; Achieve the connection from the remote machine
;;; Note: the way this currently works, the recusive call doesn't specify the next intermediate machine
;;; which will allow it to form multi-hop routes.  Note that the intermediate-machine that's bound here
;;; is the first hop from the attacker on the path to the victim

;;; This seems remarkably screwed up --- HES
;;; First of all in the pre-prequisites it says that the intermediate machine has to be reachable
;;; for ssh.  That makes no sense.  I think this condition should be nuked out.
;;; What you want to say is 
;;; 1) Find a machine that make the connection you want (this is the 2nd prerequiste)
;;; 2) Achieve remote execution on the intermediate machine somehow
;;; 3) Make the connection you wanted to begin with (i.e. not achieve as a goal but make as an action)
;;;
;;; The rules for achieving remote execution might recursively invoke a rule for achieving a connection
;;; The obvious case would be (in a 2 hop scheme) You find a machine that can connect to the victim in the desired way
;;; Then you ask to achieve remote execution on that machine
;;; If you're already running on that machine there's nothing to do
;;; But if not, then you want to find a machine that can connect to this 2nd victim machine in one of a number of ways
;;; depending on how you want to achieve remote execution on it.  Maybe you can telnet or ssh to it, or you can code inject
;;; (or ROP) on some process running on that machine and take over its execution.  Each of these requires you to be able to make
;;; a connection of a particular kind.
;;; Or you can find a 3rd machine that you can get remote execution which can talk to the 2nd machine in the appropriate way
;;; and you try to get a connection to that one.


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; 
;;; Lateral Motion reasoning: get-foothold
;;;
;;; The top level of this tries to find a foothold machine and role from which the attacker can get to the victim machine
;;; with a certain protocol (or connection-type more generally).
;;; 
;;; We start out with the attacker already at some foothold machine playing some role there (e.g. it might be running a remote shell
;;; as a particular use or it might be in control of some process on the foothold machine).
;;;
;;;
;;; There are two attack-methods:
;;; 1) The easy case: The victim will directly accept the intended connection-type from the foothold-machine
;;; 2) The hard case: The victim won't directly accept the intended connection-type from the foothold-machine
;;;    Then you have to find a machine that it will accept such a connection from.  This is the new-foothold-machine
;;;      and you have to achieve remote-execution of some kind on this new-foothold-machine starting from the original-foothold-machine
;;;      The way in which you achieve remote execution determines the new-foothold-machine
;;; Note that strategies to achieve remote-execution on the new-foothold-machine might need to first find an intermediate-foothold from which
;;; to make make the connection through which it gains remote-execution.  So we get a mutually-recursive strategy.
;;; To avoid looping back to where we started from we pass along a list of all the previous footholds to check against.
;;;
;;; Also note that each of these two has pre-requisite conditions that act as guards, i.e. you only try this strategy if
;;; the guard holds.  These guards are either positive or negative accepts-connection predications.
;;;
;;; Here ?new-foothold-machine and ?new-foothold-role are output values that are bound here
;;; and ?other-footholds are all the other footholds that the attacker has
;;; including where he's operating from now
;;; this is there mainly to avoid looping (i.e. trying from a place you've already tried)
;;;
;;; Redesign note: Passing along all these footholds should really be done by maintaining "world-states" i.e. sets of predications that 
;;; are true at certain points in the attack-plan.  The existence of these can be hidden in the macrology.  But this is for later.
;;;
;;;
;;; This used to go to some trouble to only consider machines with the enterprise of the victim
;;; I've commented that out; why not use any machine that can reach the victim?
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; This is the commented out stuff in case I think it's needed again.
	       ;; [ltms:value-of (?victim-machine site) ?site]
	       ;; [ltms:value-of (?site enterprise) ?enterprise]
	       ;; [ltms:value-of (?enterprise sites) ?foothold-site]
	       ;; [ltms:value-of (?foothold-site subnets) ?foothold-subnet]
	       ;; [ltms:value-of (?foothold-subnet computers) ?foothold-machine]
	       ;; [ltms:named-part-of ?foothold-machine os ?foothold-os-instance]
	       ;; (unify ?attacker-machine (first (first ?other-footholds)))
	       ;; (unify ?attacker-role (second (first ?other-footholds)))

	     ;; [ltms:object-type-of ?site site]
	     ;; [ltms:object-type-of ?enterprise enterprise]
	     ;; [ltms:object-type-of ?new-foothold-site site]
	     ;; [ltms:object-type-of ?new-foothold-subnet subnet]
	     ;; [ltms:object-type-of ?new-foothold-computer computer]
	     ;; [ltms:object-type-of ?new-foothold-os-instance operating-system]

(defattack-method lateral-motion
    :to-achieve [get-foothold ?victim-machine ?protocol-name ?input-context ?output-context]
    :guards ([not [place-already-visited? ?input-context ?victim-machine foothold ?protocol-name]]
	     ;; Use this method only if you can't get a connection to the victim from where you are
	     [not [accepts-connection ?victim-machine ?protocol-name ?current-foothold-machine]]
		    [not [foothold-exists ?input-context ?new-foothold-machine]]
	     )
    :bindings ([ltms:named-part-of ?victim-machine os ?victim-os]
	       [current-foothold ?input-context ?current-foothold-machine ?current-foothold-role]
	       ;; Now find somebody that can make the connection, accepts connection will find one if there is one
	       [accepts-connection ?victim-machine ?protocol-name ?new-foothold-machine]
	       ;; and make sure you're not looping back to a foothold you've already visited
	       ;; note that we've been there so that we don't loop 
	       [note-place-visited ?input-context ?victim-machine foothold ?protocol-name ?visited-context]
	       )
    :typing ([ltms:object-type-of ?victim-os operating-system]
	     [ltms:object-type-of ?victim-machine computer]
	     [ltms:object-type-of ?current-foothold-machine computer]
	     )
    :prerequisites ()
    :plan (:sequential
	   ;; Now see if the attacker can gain remote execution on the new-foothold-machine and in what role 
	   ;; (?new-foothold-role is a return value)
	   (:goal [achieve-remote-execution ?new-foothold-machine ?new-foothold-role ?visited-context ?remote-execution-context])
	   ;;If so then actually make the connection to the victim from the new foothold
	   ;; (:goal [make-connection ?victim-os-instance ?protocol-name ?remote-execution-context ?output-contet])
	   )
    :post-conditions ([has-foothold ?remote-execution-context ?new-foothold-machine ?new-foothold-role ?output-context]))

;;; Direct Method, applicable when you can get from your current foothold to the target-machine 
;;; so the foothold is the where this step is taking place from and the role is the attacker
(defattack-method get-foothold-by-protocol
    :to-achieve [get-foothold ?victim-machine ?protocol-name ?input-context ?output-context]
    :guards ([not [place-already-visited? ?input-context ?victim-machine foothold ?protocol-name]])
    :bindings ([ltms:named-part-of ?victim-machine os ?victim-os]
	       [current-foothold ?input-context ?current-foothold-machine ?current-foothold-role]
	       [unify ?input-context ?output-context]
	       ;; probably irrelevant because we're just doing an action
	       [note-place-visited ?input-context ?victim-machine foothold ?protocol-name ?visited-context])
    :typing ([ltms:object-type-of ?victim-os operating-system]
	     [ltms:object-type-of ?victim-machine computer]
	     [ltms:object-type-of ?current-foothold-machine computer])
    :prerequisites ([accepts-connection ?victim-machine ?protocol-name ?current-foothold-machine])
    :plan (:action [connect-via ?current-foothold-machine ?current-foothold-role ?victim-machine ?protocol-name])
    )

;;; Things to fix:
;;; Every use of achieve remote execution.  The idea is for each category you have to figure out 
;;; whether you can cause remote execution on the machine (from any of your footholds really) but for now from your current foothold.
;;; If not you have to find a new foothold from which you could do that.
;;; Make sure that every invocation has the current argument list with the three referring to footholds at the end.
;;;
;;; There's a negated use of accepts connection above.  Make sure that this works.


(defun reachable-for-remote-execution (victim attacker)
  (ask* `[reachable-for-remote-execution ,victim ,attacker ?protocol]
	(return-from reachable-for-remote-execution ?protocol))
  nil)

;;; These are the ways an attacker could possibly
;;; make a connection to get remote execution
(defrule can-be-reached-for-remote-execution-ssh (:backward)
  then [reachable-for-remote-execution ?victim ?attacker ssh]
  if [accepts-connection ?victim ssh ?attacker])

(defrule can-be-reached-for-remote-execution-telnet (:backward)
  then [reachable-for-remote-execution ?victim ?attacker telnet]
  if [accepts-connection ?victim telnet ?attacker])

(defrule can-be-reached-for-remote-executon-email (:backward)
  then [reachable-for-remote-execution ?victim ?attacker email]
  if [accepts-connection ?victim email ?attacker])

(defrule can-be-reached-for-remote-execution-http (:backward)
  then [reachable-for-remote-execution ?victim ?attacker http]
  if [accepts-connection ?victim http ?attacker])

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
    :to-achieve [takes-direct-control-of ?attacker ?stack-property ?network-stack ?input-context ?output-context]
    :bindings ([ltms:named-part-of ?os-instance network-monitor ?network-stack]
               [ltms:value-of (?os-instance superuser) ?superuser]
	       [ltms:value-of (?attacker machines) ?attacker-machine])
    :typing ([ltms:object-type-of ?network-stack network-stack]
             [ltms:object-type-of ?os-instance operating-system]
	     [ltms:object-type-of ?attacker-machine computer]
             [ltms:object-type-of ?superuser user])
    :plan (:sequential 
           (:goal [achieve-remote-shell ?os-instance ?superuser ?input-context ?has-shell-context])
           (:action [control ?attacker ?network-stack ?attacker-machine]))
    :post-conditions ([unify ?has-shell-context ?output-context])
    )

(defattack-method read-network-traffic
    :to-achieve [observe-network-traffic ?attacker ?subnet ?input-context ?output-context]
    :bindings ([ltms:value-of (?subnet switch) ?switch]
               [ltms:value-of (?switch os) ?os]
               [ltms:named-part-of ?os network-monitor ?network-stack])
    :typing ([ltms:object-type-of ?subnet switched-subnet]
             [ltms:object-type-of ?switch switch]
             [ltms:object-type-of ?network-stack network-stack])
    :plan (:sequential 
	   (:goal [takes-direct-control-of ?attacker network-traffic ?network-stack ?input-context ?has-control-context])
	   (:action [observe ?attacker network-traffic ?subnet]))
    :post-conditions ([unify ?has-control-context ?output-context])
    )



#|

Notes:

There are several cases where you want to get knowledge of something (e.g. a password)
and then use it later.  This can be dealt with either by careful
modularization which might be far too tricky, or by having a general
model that only runs rules on achieve-knowledge-of if there is no
predicate promising the thing is known.





This is redundant

(defrule get-knowledge-of-through-available-access-rights (:backward)
  then [achieve-knowledge-of ?attacker ?object ((:goal (know-contents-of ?object) 
                                                 :plan ?composite-plan))]
  ;; assumption is that we know the object
  if [and [ltms:object-type-of ?object computer-resource]
	  [ltms:value-of (?object machines) ?computer]
          [ltms:object-type-of ?computer computer]
          [part-of (?computer os) ?os-instance]
          [ltms:object-type-of ?os-instance operating-system]
          [requires-access-right ?object read ?capability]
	  [achieve-access-right ?attacker read ?object ?vehicle ?access-plan]
	  (unify ?composite-plan 
                 (append ?access-plan 
                         `((:action (read-using-process-capability ,?capability ,?vehicle ,?object)))))
          ])


Residencies
Formats: source, class, jar in-core-code
Transformations: compilation jarification loading


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
    :to-achieve [affect accuracy ?controller-process ?input-context ?output-context]
    :bindings ([ltms:value-of (?controller-process machines) ?controller-machine]
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
	       [ltms:named-part-of ?victim-machine os ?victim-os]
	       )
    :prerequisites ([output-of ?sensor-machine ?signal]
		    ;; the output of the sensor must be an input to 
		    ;; the controller process
		    [input-of ?controller-process ?signal]
		    [or [can-be-mastered-by ?controller-machine ?victim-machine ?bus]
			(equal ?controller-machine ?victim-machine)]
		    )
    :typing ([ltms:object-type-of ?controller-machine computer]
	     [ltms:object-type-of ?victim-machine computer]
	     [ltms:object-type-of ?controller-process control-system-process]
	     [ltms:object-type-of ?system system]
	     [ltms:object-type-of ?sensor-machine computer]
	     [ltms:object-type-of ?signal sensor-signal]
	     [ltms:object-type-of ?bus unmastered-medium]
	     [ltms:object-type-of ?victim-os operating-system]
	     )
    :plan (:sequential
	   ;; You have to specify what the entity here is
	   ;; it can either be a user or a process
	   ;; shouldn't really be in the operators that detemine how to do the remote execution
	   (:goal [achieve-remote-execution ?victim-machine ?entity ?input-context ?remote-execution-context])
	   ;; issue a false sensor data report to the controller from the attacker machine over the bus
	   ;; of the sensor type 
	   (:action [issue-false-sensor-data-report ?controller-machine ?victim-machine ?bus ?signal]))
    :post-conditions ([unify ?remote-execution-context ?output-context])
    )

; (defattack-method fake-command-data
;     :to-achieve [affect ?attacker accuracy ?controller-process]
;     :bindings ([ltms:value-of (?controller-process machines) ?machine]
; 	       [connected-to-bus ?machine ?interface ?bus ?slot]
; 	       [connected-to-bus ?other-machine ?other-interface ?bus ?other-slot]
; 	       [ltms:named-part-of ?other-machine os ?os])
;     :prerequisites ((not (eql ?machine ?other-machine))
; 		    [can-be-mastered-by ?machine ?other-machine ?bus])
;     :typing ([ltms:object-type-of ?machine computer]
; 	     [ltms:object-type-of ?other-machine computer]
; 	     [ltms:object-type-of ?os operating-system]
; 	     [ltms:object-type-of ?bus bus])
;     :plan (:sequential
; 	   (:goal [remote-execution ?attacker ?entity ?os])
; 	   (:action [issue-incorrect-setpoint ?attacker ?machine ?other-machine ?bus]))
;     )
 
(defattack-method sensor-injection-attack
    :to-achieve [affect data-integrity ?signal ?input-context ?output-context]
    :bindings ([ltms:value-of (?signal machines) ?machine]
	       [attacker-and-machine ?input-context ?attacker ?attacker-macine])
    :prerequisites ([system-role ?system sensor ?machine]
		    [is-proximate-to ?attacker ?victim radio])
    :typing ([ltms:object-type-of ?machine computer]
	     [ltms:object-type-of ?signal sensor-signal]
	     [ltms:object-type-of ?system system])
    :plan (:action [signal-noise-injection ?attacker ?machine ?signal])
    :post-conditions ([unify ?input-context ?output-context])
    )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Quick hack for botnet recruitment ala Mirai
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defattack-method recruit-to-mirai-botnet
    :to-achieve [affect independence ?cycle-pool ?input-context ?output-context]
    :bindings ([ltms:value-of (?cycle-pool machines) ?victim-machine]
	       [ltms:value-of (?cycle-pool os) ?victim-os]
	       [attacker-and-machine ?input-context ?attacker ?attacker-macine]
	       )
    :plan (:sequential
	   (:action [port-scan ?attacker ?victim-machine ?attacker-machine telnet-ports])
	   (:goal [get-foothold ?victim-machine telnet ?input-context ?foothold-context])
	   (:action [login ?attacker white-list-member ?victim-os ?foothold-machine])
	   (:action [download-malware-from-source ?attacker ?foothold-machine ?victim-machine mirai-client]))
    :post-conditions ([current-foothold ?foothold-context ?foothold-machine ?foothold-role]
		      [unify ?foothold-context ?output-context])
    )
		    